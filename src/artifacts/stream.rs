//! The downstream response, and the witness that has to exist before one can be
//! built.
//!
//! SPEC §9: "A request is authorized by its final successful policy check
//! immediately before response creation." Gate 3 asked for that to be a compile-time
//! property rather than a rule every call site remembers, so:
//!
//! * [`Authorized`] has a private unit field, so no code outside this module can
//!   name it into existence. The only constructor is [`Authorized::from_decision`],
//!   which returns `Some` for `Decision::Allow` and for nothing else.
//! * it is neither `Clone` nor `Copy`, and both response constructors take it **by
//!   value**, so one check cannot authorize two responses.
//! * [`ArtifactResponse`]'s body field is private and there is no other constructor.
//!
//! A path that skipped the final check therefore has no witness to hand over and
//! does not compile. What this cannot prove is that the snapshot the witness was
//! minted from was the newest one at that instant — SPEC §9's lock-free revocation
//! boundary makes that inherently a race, which is why the witness carries the
//! revision it was granted under.

use std::io::{self, SeekFrom};
use std::time::Duration;

use axum::body::Body;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::sync::{OwnedSemaphorePermit, mpsc};

use crate::artifacts::content::PinnedFile;
use crate::http::limits::{self, Limits};
use crate::policy::Decision;

/// How much of the file one response reads at a time. Large enough that a big
/// artifact is not a million awaits, small enough that one response is not a
/// megabyte of buffer.
const CHUNK_BYTES: usize = 64 * 1024;

/// Proof that the final policy check ran and returned `Allow`.
pub struct Authorized {
    blocklist_revision: Option<u64>,
    /// Private, and the reason this type cannot be constructed anywhere else.
    _private: (),
}

impl Authorized {
    /// The one way to obtain a witness. `Allow` and nothing else.
    pub fn from_decision(
        decision: Decision,
        blocklist_revision: Option<u64>,
    ) -> Option<Authorized> {
        match decision {
            Decision::Allow => Some(Authorized {
                blocklist_revision,
                _private: (),
            }),
            Decision::Unavailable | Decision::Deny(_) | Decision::Hold { .. } => None,
        }
    }

    /// The revision the witness was granted under, so a decision log line can say
    /// which policy allowed the bytes that went out.
    pub fn blocklist_revision(&self) -> Option<u64> {
        self.blocklist_revision
    }
}

/// An inclusive byte range, as HTTP spells them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ByteRange {
    pub start: u64,
    pub end: u64,
}

impl ByteRange {
    pub fn length(&self) -> u64 {
        self.end.saturating_sub(self.start).saturating_add(1)
    }
}

/// What a `Range` header asked for. SPEC §9: one range is honoured, several are
/// ignored and the complete verified body is returned.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RangeRequest {
    Whole,
    One(ByteRange),
    Unsatisfiable,
}

/// `bytes=a-b`, `bytes=a-` and `bytes=-n` over a body of `total` bytes.
pub fn parse_range(header: Option<&str>, total: u64) -> RangeRequest {
    let Some(value) = header else {
        return RangeRequest::Whole;
    };
    let Some(spec) = value.trim().strip_prefix("bytes=") else {
        // An unsupported unit is not an error: RFC 9110 says to ignore it.
        return RangeRequest::Whole;
    };
    if spec.contains(',') {
        // Several ranges: ignored, complete body (SPEC §9).
        return RangeRequest::Whole;
    }

    let Some((first, last)) = spec.split_once('-') else {
        return RangeRequest::Whole;
    };
    let (first, last) = (first.trim(), last.trim());

    let range = match (first.is_empty(), last.is_empty()) {
        // `bytes=-n`: the final n bytes.
        (true, false) => {
            let Ok(suffix) = last.parse::<u64>() else {
                return RangeRequest::Whole;
            };
            if suffix == 0 {
                return RangeRequest::Unsatisfiable;
            }
            let suffix = suffix.min(total);
            ByteRange {
                start: total - suffix,
                end: total.saturating_sub(1),
            }
        }
        (false, true) => {
            let Ok(start) = first.parse::<u64>() else {
                return RangeRequest::Whole;
            };
            ByteRange {
                start,
                end: total.saturating_sub(1),
            }
        }
        (false, false) => {
            let (Ok(start), Ok(end)) = (first.parse::<u64>(), last.parse::<u64>()) else {
                return RangeRequest::Whole;
            };
            ByteRange {
                start,
                end: end.min(total.saturating_sub(1)),
            }
        }
        (true, true) => return RangeRequest::Whole,
    };

    if total == 0 || range.start >= total || range.start > range.end {
        return RangeRequest::Unsatisfiable;
    }
    RangeRequest::One(range)
}

/// A response built from a witness. There is no other way to build one with a body.
pub struct ArtifactResponse {
    status: StatusCode,
    total_length: u64,
    range: Option<ByteRange>,
    body: Option<PinnedFile>,
    /// The caller's share of `max_active_requests`, held until the last body byte
    /// has left (SPEC §9: "timeout or disconnect releases file pins and permits").
    permit: Option<OwnedSemaphorePermit>,
    write_idle: Duration,
    lifetime: Duration,
}

impl ArtifactResponse {
    /// Consumes the witness.
    pub fn with_body(
        auth: Authorized,
        file: PinnedFile,
        range: Option<ByteRange>,
        total_length: u64,
    ) -> ArtifactResponse {
        tracing::debug!(
            blocklist_revision = ?auth.blocklist_revision(),
            bytes = range.map_or(total_length, |range| range.length()),
            "authorized an artifact response"
        );
        ArtifactResponse {
            status: if range.is_some() {
                StatusCode::PARTIAL_CONTENT
            } else {
                StatusCode::OK
            },
            total_length,
            range,
            body: Some(file),
            permit: None,
            write_idle: limits::WRITE_IDLE,
            lifetime: limits::RESPONSE_LIFETIME,
        }
    }

    /// `HEAD`: every check has run, including a cold verification, and no body is
    /// sent. It still requires the witness.
    pub fn head_only(auth: Authorized, total_length: u64) -> ArtifactResponse {
        tracing::debug!(
            blocklist_revision = ?auth.blocklist_revision(),
            "authorized an artifact HEAD response"
        );
        ArtifactResponse {
            status: StatusCode::OK,
            total_length,
            range: None,
            body: None,
            permit: None,
            write_idle: limits::WRITE_IDLE,
            lifetime: limits::RESPONSE_LIFETIME,
        }
    }

    /// An unsatisfiable range on a body that policy *did* authorize: ordinary `416`
    /// semantics with the total length, and still no body without a witness.
    pub fn range_not_satisfiable(auth: Authorized, total_length: u64) -> ArtifactResponse {
        tracing::debug!(
            blocklist_revision = ?auth.blocklist_revision(),
            "authorized an artifact response, then found the requested range unsatisfiable"
        );
        ArtifactResponse {
            status: StatusCode::RANGE_NOT_SATISFIABLE,
            total_length,
            range: None,
            body: None,
            permit: None,
            write_idle: limits::WRITE_IDLE,
            lifetime: limits::RESPONSE_LIFETIME,
        }
    }

    /// Hands the response the permit its request took and the deadlines it runs
    /// under. The permit is released when the body ends — completed, timed out, or
    /// with the client gone — and not when the handler returns.
    pub fn under(mut self, limits: &Limits, permit: OwnedSemaphorePermit) -> ArtifactResponse {
        self.permit = Some(permit);
        self.write_idle = limits.write_idle();
        self.lifetime = limits.response_lifetime();
        self
    }
}

impl IntoResponse for ArtifactResponse {
    fn into_response(self) -> Response {
        let unsatisfiable = self.status == StatusCode::RANGE_NOT_SATISFIABLE;
        // `HEAD` reports the length of the entity it would have sent; a `416` has no
        // entity at all, and says so with `bytes */total`.
        let length = if unsatisfiable {
            0
        } else {
            self.range.map_or(self.total_length, |range| range.length())
        };
        let content_range = match (unsatisfiable, self.range) {
            (true, _) => Some(format!("bytes */{}", self.total_length)),
            (false, Some(range)) => Some(format!(
                "bytes {}-{}/{}",
                range.start, range.end, self.total_length
            )),
            (false, None) => None,
        };

        let body = match self.body {
            None => Body::empty(),
            Some(file) => {
                let start = self.range.map_or(0, |range| range.start);
                file_body(
                    file,
                    start,
                    length,
                    self.write_idle,
                    self.lifetime,
                    self.permit,
                )
            }
        };

        let mut response = Response::new(body);
        *response.status_mut() = self.status;
        let headers = response.headers_mut();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
        if let Ok(value) = HeaderValue::from_str(&length.to_string()) {
            headers.insert(header::CONTENT_LENGTH, value);
        }
        if let Some(content_range) = content_range
            && let Ok(value) = HeaderValue::from_str(&content_range)
        {
            headers.insert(header::CONTENT_RANGE, value);
        }
        response
    }
}

/// The already verified local file, read in bounded chunks. Nothing re-hashes it:
/// SPEC §9 says verified cache hits are not rehashed on every request.
///
/// The bytes are produced by a task of their own, handing chunks to the response
/// through a channel one chunk deep. That is what makes the two SPEC §9 deadlines
/// enforceable at all: a slow consumer shows up as a `send` that does not complete,
/// and a task blocked in `send` is still scheduled and can still notice a deadline —
/// whereas a stream polled only when the client is ready cannot time its own absence.
///
/// Whichever way the task ends, the file pin and the request permit it owns are
/// released with it (SPEC §9: "timeout or disconnect releases file pins and permits").
fn file_body(
    file: PinnedFile,
    start: u64,
    length: u64,
    write_idle: Duration,
    lifetime: Duration,
    permit: Option<OwnedSemaphorePermit>,
) -> Body {
    let (chunks, receiver) = mpsc::channel::<Result<Bytes, io::Error>>(1);

    tokio::spawn(async move {
        // Both are owned here and dropped here, on every path out.
        let _permit = permit;
        let mut file = file;

        if tokio::time::timeout(
            lifetime,
            produce(&mut file, start, length, write_idle, &chunks),
        )
        .await
        .is_err()
        {
            tracing::info!(
                seconds = lifetime.as_secs(),
                "an artifact response reached its lifetime limit; releasing its pin and permit"
            );
        }
    });

    Body::from_stream(futures_util::stream::unfold(
        receiver,
        |mut receiver| async move { receiver.recv().await.map(|chunk| (chunk, receiver)) },
    ))
}

/// Reads `length` bytes from `start` into `chunks`, giving up if the consumer takes
/// longer than `write_idle` over any one of them.
async fn produce(
    file: &mut PinnedFile,
    start: u64,
    length: u64,
    write_idle: Duration,
    chunks: &mpsc::Sender<Result<Bytes, io::Error>>,
) {
    if let Err(err) = file.file_mut().seek(SeekFrom::Start(start)).await {
        let _ = chunks.send(Err(err)).await;
        return;
    }

    let mut remaining = length;
    while remaining > 0 {
        let wanted = remaining.min(CHUNK_BYTES as u64) as usize;
        let mut buffer = vec![0u8; wanted];
        let read = match file.file_mut().read(&mut buffer).await {
            // The file is shorter than its mapping said; the response ends here
            // rather than inventing padding.
            Ok(0) => return,
            Ok(read) => read,
            Err(err) => {
                let _ = chunks.send(Err(err)).await;
                return;
            }
        };
        buffer.truncate(read);
        remaining -= read as u64;

        match tokio::time::timeout(write_idle, chunks.send(Ok(Bytes::from(buffer)))).await {
            Ok(Ok(())) => {}
            // The client stopped reading and the channel filled behind it.
            Err(_elapsed) => {
                tracing::info!(
                    seconds = write_idle.as_secs(),
                    "an artifact response hit the downstream write-idle limit; releasing its \
                     pin and permit"
                );
                return;
            }
            // The client went away, so there is nobody to send the rest to.
            Ok(Err(_closed)) => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::DenyReason;

    /// The whole compile-time guard in one assertion: only `Allow` mints a witness,
    /// and every other decision has nothing to build a body with.
    #[test]
    fn only_an_allow_mints_a_witness() {
        assert!(Authorized::from_decision(Decision::Allow, Some(7)).is_some());
        assert!(
            Authorized::from_decision(Decision::Deny(DenyReason::BlockedDigest), Some(7)).is_none()
        );
        assert!(
            Authorized::from_decision(
                Decision::Hold {
                    eligible_at_micros: 1
                },
                Some(7)
            )
            .is_none()
        );
        assert!(Authorized::from_decision(Decision::Unavailable, None).is_none());
    }

    #[test]
    fn a_single_range_is_honoured_and_several_are_ignored() {
        assert_eq!(parse_range(None, 10), RangeRequest::Whole);
        assert_eq!(
            parse_range(Some("bytes=2-5"), 10),
            RangeRequest::One(ByteRange { start: 2, end: 5 })
        );
        assert_eq!(
            parse_range(Some("bytes=4-"), 10),
            RangeRequest::One(ByteRange { start: 4, end: 9 })
        );
        assert_eq!(
            parse_range(Some("bytes=-3"), 10),
            RangeRequest::One(ByteRange { start: 7, end: 9 })
        );
        assert_eq!(
            parse_range(Some("bytes=0-99"), 10),
            RangeRequest::One(ByteRange { start: 0, end: 9 }),
            "an end past the body is clamped, which is ordinary 206 semantics"
        );
        assert_eq!(
            parse_range(Some("bytes=0-1,4-5"), 10),
            RangeRequest::Whole,
            "SPEC §9: ignore unsupported multiple ranges and return the complete body"
        );
        assert_eq!(parse_range(Some("items=0-1"), 10), RangeRequest::Whole);
    }

    #[test]
    fn a_range_past_the_end_is_unsatisfiable() {
        assert_eq!(
            parse_range(Some("bytes=10-12"), 10),
            RangeRequest::Unsatisfiable
        );
        assert_eq!(
            parse_range(Some("bytes=5-2"), 10),
            RangeRequest::Unsatisfiable
        );
        assert_eq!(
            parse_range(Some("bytes=0-0"), 0),
            RangeRequest::Unsatisfiable
        );
    }
}
