//! The single place SPEC §11's failure table is encoded.
//!
//! Slice 1 encoded the two rows it reached; slice 4 added the three upstream rows,
//! because the outbound boundary is the first code that can produce them; slice 5
//! added the `403` held and blocked rows with `eligible_at` and `Retry-After`, `400`,
//! and the two remaining storage `503`s, because the metadata path is the first code
//! that can produce those. Slice 9 closed the table: the `405` and `406` rows, the
//! internal failure that has no row of its own, and the request ID that is now the
//! one `src/http/logging.rs` assigned rather than a number invented here.
//!
//! What a body may carry is fixed by SPEC §11 and by nothing else: `error`, `reason`,
//! `request_id`, and `eligible_at` on a cooldown. Every `reason` below is a constant
//! written here. No upstream URL, upstream header, filesystem path, or source error's
//! `Display` output reaches a client — those go to the log, where the operator who
//! needs them can see them and the client cannot.

use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use crate::http::logging;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ApiError {
    /// Held by the age rule. SPEC §11 requires `eligible_at` and a numeric
    /// `Retry-After` on this row, so the deadline travels with the error rather than
    /// being recomputed where the response is built.
    Held {
        eligible_at_micros: i64,
        retry_after_seconds: u64,
    },
    /// Denied by the blocklist, or by a publication time that cannot be trusted.
    /// There is no deadline: a block is not something to wait out.
    Blocked {
        reason: &'static str,
    },
    /// Unknown package, reference, route, or upstream removal.
    NotFound,
    InvalidInput(&'static str),
    /// A route this server serves, asked for with a method it does not. Axum adds the
    /// `Allow` header to the response this becomes.
    MethodNotAllowed,
    /// The client accepts no representation this server produces. SPEC §11's `406`.
    NotAcceptable,
    /// Missing or expired blocklist: no policy is in force, so nothing is served.
    PolicyUnavailable,
    /// The storage task refused work because its queue is full.
    Overloaded,
    /// Local capacity could not be reserved or reclaimed for a cold download
    /// (SPEC §10). Never a reason to relax policy.
    CapacityExhausted,
    /// Storage is unusable, so no state change a response would depend on can be
    /// committed (SPEC §10).
    StorageUnusable,
    /// Work this instance started did not finish, for a reason that is neither
    /// upstream's, nor policy's, nor a bound being reached — a transfer task that
    /// died, say.
    ///
    /// SPEC §11's table has no internal-failure row, and slice 9 owns that table.
    /// It needs none: the `503` row is the instance-local row, meaning "this instance
    /// cannot serve it now; a later attempt may", and that is exactly what this is.
    /// `502` would blame upstream for a fault that is ours, and would send an operator
    /// to read the wrong logs. It is separate from [`ApiError::Overloaded`] only so
    /// that the reason a client and a log line are given is true: nothing was at
    /// capacity.
    InternalFailure,
    /// Upstream could not be reached, refused the request, or was refused by the
    /// outbound boundary. SPEC §11 puts every one of those in the same `502` row,
    /// because the difference is ours to log and not the client's to act on.
    UpstreamFailure,
    /// Upstream answered, but not with a document we can use.
    UpstreamInvalid,
    /// Downloaded bytes disagree with the advertised integrity, the declared size,
    /// or the digests permanently pinned for this reference (SPEC §9, STATE-01).
    IntegrityMismatch,
    /// The one upstream failure SPEC §11 separates out, because a client may
    /// reasonably retry it.
    UpstreamTimeout,
}

impl ApiError {
    /// A hold, with its `Retry-After` computed from the one `now` the decision was
    /// made against. Rounded up, and at least one second: a `Retry-After: 0` invites
    /// a client to spin.
    pub fn held(eligible_at_micros: i64, now_utc_micros: i64) -> ApiError {
        let remaining = eligible_at_micros.saturating_sub(now_utc_micros).max(0);
        let retry_after_seconds = (remaining as u64).div_ceil(1_000_000).max(1);
        ApiError::Held {
            eligible_at_micros,
            retry_after_seconds,
        }
    }

    pub fn status(&self) -> StatusCode {
        match self {
            ApiError::Held { .. } | ApiError::Blocked { .. } => StatusCode::FORBIDDEN,
            ApiError::NotFound => StatusCode::NOT_FOUND,
            ApiError::InvalidInput(_) => StatusCode::BAD_REQUEST,
            ApiError::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            ApiError::NotAcceptable => StatusCode::NOT_ACCEPTABLE,
            ApiError::PolicyUnavailable
            | ApiError::Overloaded
            | ApiError::CapacityExhausted
            | ApiError::StorageUnusable
            | ApiError::InternalFailure => StatusCode::SERVICE_UNAVAILABLE,
            ApiError::UpstreamFailure | ApiError::UpstreamInvalid | ApiError::IntegrityMismatch => {
                StatusCode::BAD_GATEWAY
            }
            ApiError::UpstreamTimeout => StatusCode::GATEWAY_TIMEOUT,
        }
    }

    /// The stable machine-readable token clients match on.
    pub fn error_code(&self) -> &'static str {
        match self {
            ApiError::Held { .. } => "HELD",
            ApiError::Blocked { .. } => "BLOCKED",
            ApiError::NotFound => "NOT_FOUND",
            ApiError::InvalidInput(_) => "INVALID_INPUT",
            ApiError::MethodNotAllowed => "METHOD_NOT_ALLOWED",
            ApiError::NotAcceptable => "NOT_ACCEPTABLE",
            ApiError::PolicyUnavailable => "POLICY_UNAVAILABLE",
            ApiError::Overloaded => "OVERLOADED",
            ApiError::CapacityExhausted => "CAPACITY_EXHAUSTED",
            ApiError::StorageUnusable => "STORAGE_UNUSABLE",
            ApiError::InternalFailure => "INTERNAL_FAILURE",
            ApiError::UpstreamFailure => "UPSTREAM_FAILURE",
            ApiError::UpstreamInvalid => "UPSTREAM_INVALID",
            ApiError::IntegrityMismatch => "INTEGRITY_MISMATCH",
            ApiError::UpstreamTimeout => "UPSTREAM_TIMEOUT",
        }
    }

    /// The client-visible explanation. Every arm is a constant written in this file:
    /// nothing derived from a request, an upstream answer, or a source error's
    /// `Display` output can travel out through here.
    pub fn reason(&self) -> String {
        match self {
            ApiError::Held { .. } => "the release has not completed its cooldown period".to_owned(),
            ApiError::Blocked { reason } => (*reason).to_owned(),
            ApiError::NotFound => "no such route or resource".to_owned(),
            ApiError::InvalidInput(reason) => (*reason).to_owned(),
            ApiError::MethodNotAllowed => {
                "this route does not support that request method".to_owned()
            }
            ApiError::NotAcceptable => {
                "no representation this server produces was accepted".to_owned()
            }
            ApiError::PolicyUnavailable => {
                "no valid blocklist is loaded, so no package can be judged eligible".to_owned()
            }
            ApiError::Overloaded => "the service is at capacity".to_owned(),
            ApiError::CapacityExhausted => "local storage could not take the artifact".to_owned(),
            ApiError::StorageUnusable => {
                "local storage is unusable, so no decision can be committed".to_owned()
            }
            ApiError::InternalFailure => {
                "the request could not be completed; a later attempt may succeed".to_owned()
            }
            ApiError::UpstreamFailure => "the upstream registry could not be reached".to_owned(),
            ApiError::UpstreamInvalid => {
                "the upstream registry returned an unusable document".to_owned()
            }
            ApiError::IntegrityMismatch => {
                "the artifact does not match its expected digests".to_owned()
            }
            ApiError::UpstreamTimeout => "the upstream registry did not answer in time".to_owned(),
        }
    }

    /// RFC 3339, cooldown only (SPEC §11).
    fn eligible_at(&self) -> Option<String> {
        match self {
            ApiError::Held {
                eligible_at_micros, ..
            } => jiff::Timestamp::from_microsecond(*eligible_at_micros)
                .ok()
                .map(|timestamp| timestamp.to_string()),
            _ => None,
        }
    }
}

/// SPEC §11: policy errors carry `error`, `reason`, `request_id`, and, for
/// cooldown, `eligible_at`.
#[derive(Serialize)]
pub struct ErrorBody {
    pub error: &'static str,
    pub reason: String,
    pub request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eligible_at: Option<String>,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = ErrorBody {
            error: self.error_code(),
            reason: self.reason(),
            // The ID this request already has, so the one a client is told and the one
            // its decision line carries are the same string rather than two counters
            // that happen to agree.
            request_id: logging::request_id(),
            eligible_at: self.eligible_at(),
        };

        let mut response = (self.status(), Json(body)).into_response();
        if let ApiError::Held {
            retry_after_seconds,
            ..
        } = self
            && let Ok(value) = HeaderValue::from_str(&retry_after_seconds.to_string())
        {
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
        // Carried out to `logging::decide`, which is outside every handler and
        // therefore the only place that can log one line for every answer including
        // the ones the router produces itself. Extensions never reach the wire.
        response.extensions_mut().insert(self);
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hold_carries_a_deadline_and_a_whole_number_of_seconds() {
        let now = 1_000_000_000i64;
        let held = ApiError::held(now + 1_500_000, now);
        assert_eq!(
            held,
            ApiError::Held {
                eligible_at_micros: now + 1_500_000,
                retry_after_seconds: 2,
            },
            "a part second rounds up, so a client that obeys it does not come back early"
        );
        assert_eq!(held.status(), StatusCode::FORBIDDEN);
        assert!(held.eligible_at().is_some());

        assert_eq!(
            ApiError::held(now, now),
            ApiError::Held {
                eligible_at_micros: now,
                retry_after_seconds: 1,
            },
            "never zero: a Retry-After of 0 invites a client to spin"
        );
    }

    #[test]
    fn only_a_hold_carries_eligible_at() {
        assert!(
            ApiError::Blocked {
                reason: "the package is blocked"
            }
            .eligible_at()
            .is_none(),
            "a block has no deadline, so it must not look like one"
        );
        assert!(ApiError::NotFound.eligible_at().is_none());
    }
}
