//! Re-admission of a read whose finished response the release gate refused (SPEC §9 final authorisation, FIX-16-A).
//!
//! Any policy publication (a sync that changed anything, a new shared-service snapshot) between a request's
//! authorisation and its release refuses the finished response: it was decided under a policy that is no longer the
//! current one. Reporting that as a 503 punishes a client for a change that usually concerns neither it nor its request,
//! and `go` and Cargo do not retry a 503. So the one shared layer around every route admits a GET or HEAD again, from
//! the start, under the NEW policy: the refused response is dropped before a byte leaves, the new principal and
//! snapshot decide everything again (a block published meanwhile wins; nothing admitted under the old policy is
//! served), and a change that keeps landing is reported after `ATTEMPTS` admissions.

use axum::body::Body;
use axum::extract::Request;
use axum::http::Method;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::http::error::ApiError;

/// At most this many admissions of one request.
pub const ATTEMPTS: usize = 3;

/// Marks a response as the release gate's refusal (the only thing this layer retries).
#[derive(Clone, Copy, Debug)]
pub struct GateRefused;

/// The 503 of a refused release, marked so [`readmit`] can tell it from any other `POLICY_UNAVAILABLE`.
pub fn refusal() -> Response {
    let mut response = ApiError::PolicyUnavailable.into_response();
    response.extensions_mut().insert(GateRefused);
    response
}

/// The layer: GET and HEAD only (no body to replay); everything else passes through untouched.
pub async fn readmit(request: Request, next: Next) -> Response {
    if !matches!(*request.method(), Method::GET | Method::HEAD) {
        return next.run(request).await;
    }
    let (parts, _body) = request.into_parts();
    let mut attempt = 1;
    loop {
        let mut again = Request::new(Body::empty());
        *again.method_mut() = parts.method.clone();
        *again.uri_mut() = parts.uri.clone();
        *again.version_mut() = parts.version;
        *again.headers_mut() = parts.headers.clone();
        *again.extensions_mut() = parts.extensions.clone();
        let response = next.clone().run(again).await;
        if response.extensions().get::<GateRefused>().is_none() || attempt >= ATTEMPTS {
            return response;
        }
        attempt += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::routing::any;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tower::ServiceExt;

    /// A router whose one handler refuses the release `refusals` times, then answers 200; returns it with its call count.
    fn router(refusals: usize) -> (Router, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&calls);
        let handler = move || {
            let seen = Arc::clone(&seen);
            async move {
                if seen.fetch_add(1, Ordering::SeqCst) < refusals {
                    refusal()
                } else {
                    axum::http::StatusCode::OK.into_response()
                }
            }
        };
        (
            Router::new()
                .route("/x", any(handler))
                .layer(axum::middleware::from_fn(readmit)),
            calls,
        )
    }

    async fn send(method: Method, refusals: usize) -> (u16, usize) {
        let (app, calls) = router(refusals);
        let request = Request::builder()
            .method(method)
            .uri("/x")
            .body(Body::empty())
            .unwrap();
        let status = app.oneshot(request).await.unwrap().status().as_u16();
        (status, calls.load(Ordering::SeqCst))
    }

    /// L1: a refused write is never replayed (one effect, the refusal is reported), a read is admitted at most
    /// `ATTEMPTS` times: two refusals then success is 200 on the third admission, three refusals is a 503 after exactly three.
    #[tokio::test]
    async fn only_reads_are_admitted_again_and_at_most_three_times() {
        for method in [Method::PUT, Method::POST, Method::DELETE, Method::PATCH] {
            assert_eq!(
                send(method.clone(), 1).await,
                (503, 1),
                "{method} is never replayed"
            );
        }
        assert_eq!(send(Method::GET, 0).await, (200, 1));
        assert_eq!(
            send(Method::GET, 2).await,
            (200, 3),
            "refused twice, served on the third admission"
        );
        assert_eq!(
            send(Method::GET, 3).await,
            (503, 3),
            "refused three times: reported, not tried a fourth time"
        );
        assert_eq!(send(Method::GET, 99).await, (503, 3));
        assert_eq!(send(Method::HEAD, 2).await, (200, 3));
    }
}
