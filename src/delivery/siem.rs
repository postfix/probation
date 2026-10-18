//! The SIEM sink: decision records batched and `POST`ed to an operator's collector as
//! newline-delimited JSON.
//!
//! Everything the collector can do to this process is bounded here. The client carries
//! its own per-attempt timeout, the hold on an undelivered batch is bounded by shutdown
//! and by the queue budget rather than by a retry count, and the drain is cut off by a
//! deadline the caller imposes rather than one the request is trusted to honour. A
//! collector that stops answering costs records — which are counted — and nothing else.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use reqwest::header::{CONTENT_TYPE, HeaderName, HeaderValue};
use reqwest::{Client, StatusCode};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use url::Url;

use super::counters::SinkCounters;
use super::{Queue, Record};

/// How many records one `POST` carries at most.
const BATCH_RECORDS: usize = 256;

/// How long a partial batch waits for company before it goes anyway.
const BATCH_INTERVAL: Duration = Duration::from_secs(2);

/// The backoff before each retry. The ladder is climbed once and its last entry, 2 s,
/// is then the interval between every further attempt while the collector is
/// unreachable: the batch is held, not dropped.
const BACKOFF: [Duration; 3] = [
    Duration::from_millis(100),
    Duration::from_millis(500),
    Duration::from_secs(2),
];

/// The same deadline the file sink drains under, imposed the same way: by the caller,
/// so it holds however wedged the collector is.
const DRAIN_DEADLINE: Duration = Duration::from_secs(5);

/// Batches records and ships them until the drain token fires.
///
/// The credential is passed in rather than read here, so [`super::build`] owns the one
/// point at which the environment is read and the one point at which a bad value fails
/// startup.
pub(super) async fn run(
    client: Client,
    url: Url,
    auth: Option<(HeaderName, HeaderValue)>,
    mut queue: Queue,
    drain: CancellationToken,
    counters: Arc<SinkCounters>,
) {
    let mut batch: Vec<Record> = Vec::new();
    // Meaningful only while `batch` is non-empty, which is exactly when its branch is
    // enabled. Set when the first record of a batch arrives, so the two seconds are
    // counted from the oldest record rather than from the newest.
    let mut deadline = Instant::now();

    loop {
        tokio::select! {
            received = queue.recv() => match received {
                Some(record) => {
                    if batch.is_empty() {
                        deadline = Instant::now() + BATCH_INTERVAL;
                    }
                    batch.push(record);
                    if batch.len() >= BATCH_RECORDS {
                        send(&client, &url, auth.as_ref(), &mut batch, &counters, &drain).await;
                    }
                }
                None => break,
            },
            () = tokio::time::sleep_until(deadline), if !batch.is_empty() => {
                send(&client, &url, auth.as_ref(), &mut batch, &counters, &drain).await;
            }
            () = drain.cancelled() => {
                // Whatever is already queued, and nothing more — the same reasoning as
                // the file sink: the last `App` is dropped only after this task has
                // been joined, so waiting on sender closure would deadlock.
                let _ = tokio::time::timeout(DRAIN_DEADLINE, async {
                    while let Some(record) = queue.try_recv() {
                        batch.push(record);
                        if batch.len() >= BATCH_RECORDS {
                            send(&client, &url, auth.as_ref(), &mut batch, &counters, &drain).await;
                        }
                    }
                    if !batch.is_empty() {
                        send(&client, &url, auth.as_ref(), &mut batch, &counters, &drain).await;
                    }
                })
                .await;

                // What the deadline cut short: the batch still in hand, and anything
                // left on the queue behind it. Counted rather than lost quietly.
                let lost = (batch.len() + queue.len()) as u64;
                if lost != 0 {
                    counters.lose(lost);
                }
                break;
            }
        }
    }
}

/// Ships `batch` and empties it, retrying what is worth retrying.
///
/// **A batch that cannot be delivered is counted whole.** One record a collector
/// rejects therefore costs up to 255 good records beside it. That is the accepted
/// Gate 3 C21 limit, not an oversight: isolating the offending record costs either a
/// burst of up to 256 `POST`s at a collector that is already failing, or a bisection
/// ladder, and both make a bad moment worse. The file sink has no equivalent failure
/// mode and is the answer for an operator who needs completeness.
async fn send(
    client: &Client,
    url: &Url,
    auth: Option<&(HeaderName, HeaderValue)>,
    batch: &mut Vec<Record>,
    counters: &SinkCounters,
    drain: &CancellationToken,
) {
    // Only what made it into the body: a record that would not serialize is counted
    // here, once, and not again with the batch.
    let mut count = 0;
    let mut body = String::new();
    for record in batch.drain(..) {
        if let Ok(line) = serde_json::to_string(&record) {
            body.push_str(&line);
            body.push('\n');
            count += 1;
        } else {
            counters.lose(1);
        }
    }
    // From here the records exist nowhere else: they are off the queue and out of
    // `batch`, so the caller's own `batch.len() + queue.len()` can no longer see them and
    // this guard is the only thing that can still count them. It matters because this
    // whole future is awaited inside the drain deadline's `timeout`, and a future cut
    // off at an await point is dropped rather than resumed — `Drop` runs, so
    // cancellation is counted by construction rather than by remembering to.
    let mut unsent = Unsent { count, counters };
    // Cloned once per attempt, and a `Bytes` clone is a refcount bump rather than the
    // batch again.
    let body = Bytes::from(body);

    let mut attempt = 0;
    loop {
        let mut request = client
            .post(url.clone())
            .header(CONTENT_TYPE, "application/x-ndjson")
            .body(body.clone());
        if let Some((name, value)) = auth {
            request = request.header(name.clone(), value.clone());
        }

        let retryable = match request.send().await {
            Ok(response) if response.status().is_success() => {
                unsent.delivered();
                return;
            }
            // A `3xx` lands here too: redirects are disabled, so a collector that
            // answers one has sent this batch nowhere. Nothing about a stale
            // credential or a rejected payload changes on a second attempt, so only a
            // server error or an explicit throttle is retried.
            Ok(response) => {
                let status = response.status();
                tracing::warn!(
                    status = status.as_u16(),
                    "the SIEM collector refused a batch of decision records"
                );
                status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS
            }
            Err(err) => {
                // reqwest's error text carries the whole URL, and a collector token can
                // sit in its path or query. The origin says which collector.
                tracing::warn!(
                    collector = %url.origin().ascii_serialization(),
                    error = %err.without_url(),
                    "a batch of decision records could not be sent to the SIEM collector"
                );
                true
            }
        };

        if !retryable {
            break;
        }
        // The hold: a server error or throttle is retried for as long as the drain
        // has not begun, so the queue behind this batch accumulates instead of the
        // batch being discarded. Shutdown must be able to interrupt it, or it would
        // block on this task for as long as the collector is down.
        let backoff = BACKOFF[attempt.min(BACKOFF.len() - 1)];
        tokio::select! {
            () = tokio::time::sleep(backoff) => {}
            // `unsent` is still armed, and its `Drop` counts the batch.
            () = drain.cancelled() => return,
        }
        attempt += 1;
    }

    tracing::warn!(
        records = count,
        "a batch of decision records was dropped after the SIEM collector refused it"
    );
    // `unsent` is still armed, and its `Drop` is what does the counting.
}

/// A batch that has left `batch` and has not been delivered yet.
///
/// It adds to `counters` exactly once, and only ever adds: the counter is read and reset
/// with `swap(0, ..)` by the summary path, so a pessimistic add followed by a subtract
/// could underflow a counter someone had just reset and wrap to near `u64::MAX`.
struct Unsent<'a> {
    count: u64,
    counters: &'a SinkCounters,
}

impl Unsent<'_> {
    /// The collector took the batch: there is nothing to count.
    fn delivered(&mut self) {
        self.count = 0;
    }
}

impl Drop for Unsent<'_> {
    fn drop(&mut self) {
        if self.count != 0 {
            self.counters.lose(self.count);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// rl7, the two SIEM sites. A collector that accepts and never answers holds the
    /// first full batch inside `send` until the drain deadline cuts it off; that batch
    /// is counted by `Unsent::drop` (256) and the records still queued behind it by the
    /// deadline site, so a window of 300 needs both.
    #[tokio::test]
    async fn rl7_siem_drain_deadline_and_unsent_count_in_the_window() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        let hold = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });

        let total = BATCH_RECORDS + 44;
        let (sink, queue) = crate::delivery::channel(total);
        for _ in 0..total {
            sink.push(crate::delivery::tests::decision());
        }
        let drain = CancellationToken::new();
        drain.cancel();
        let counters = Arc::new(SinkCounters::new());
        run(
            Client::new(),
            url,
            None,
            queue,
            drain,
            Arc::clone(&counters),
        )
        .await;
        hold.abort();

        assert_eq!(counters.take_window(), total as u64);
    }

    /// The sink stops once every sender is gone, and a drain with nothing queued
    /// sends nothing and counts nothing. The URL is never contacted.
    #[tokio::test]
    async fn run_returns_on_a_closed_queue_and_on_an_empty_drain() {
        let url = Url::parse("http://127.0.0.1:9/").unwrap();
        let counters = Arc::new(SinkCounters::new());

        let (sink, queue) = crate::delivery::channel(1);
        drop(sink);
        let open = CancellationToken::new();
        run(
            Client::new(),
            url.clone(),
            None,
            queue,
            open,
            Arc::clone(&counters),
        )
        .await;

        let (_sink, queue) = crate::delivery::channel(1);
        let drain = CancellationToken::new();
        drain.cancel();
        run(
            Client::new(),
            url,
            None,
            queue,
            drain,
            Arc::clone(&counters),
        )
        .await;
        assert_eq!(counters.total(), 0);
    }

    /// rl7, the `Unsent::drop` site on its own: an undelivered batch is counted whole,
    /// and a delivered one is not.
    #[test]
    fn rl7_unsent_counts_an_undelivered_batch() {
        let counters = SinkCounters::new();
        drop(Unsent {
            count: 5,
            counters: &counters,
        });
        let mut delivered = Unsent {
            count: 7,
            counters: &counters,
        };
        delivered.delivered();
        drop(delivered);
        assert_eq!(counters.take_window(), 5);
    }
}
