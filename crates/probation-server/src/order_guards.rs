//! Small synchronous guards the async snapshot handler calls in a fixed order, so the order
//! is one lowerable function rather than an `await` sequence (03 § Order guards). That the
//! handler calls the guard before `load_policy_snapshot` remains a runtime and review
//! obligation.

use axum::http::StatusCode;

/// What the service-key lookup found.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Standing {
    Live,
    Suspended,
    Unknown,
}

/// Standing first, then the fetch budget: an unknown or revoked key is `401` and a suspended
/// organisation `403` whatever the budget says (no budget oracle for a bad key), and only a
/// live key can be told `429`. `Ok` is the only way to the policy body.
pub(crate) fn snapshot_order(standing: Standing, within_budget: bool) -> Result<(), StatusCode> {
    match standing {
        Standing::Unknown => Err(StatusCode::UNAUTHORIZED),
        Standing::Suspended => Err(StatusCode::FORBIDDEN),
        Standing::Live if !within_budget => Err(StatusCode::TOO_MANY_REQUESTS),
        Standing::Live => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_order_checks_standing_before_budget() {
        assert_eq!(
            snapshot_order(Standing::Unknown, false),
            Err(StatusCode::UNAUTHORIZED)
        );
        assert_eq!(
            snapshot_order(Standing::Suspended, false),
            Err(StatusCode::FORBIDDEN)
        );
        assert_eq!(
            snapshot_order(Standing::Live, false),
            Err(StatusCode::TOO_MANY_REQUESTS)
        );
        assert_eq!(snapshot_order(Standing::Live, true), Ok(()));
    }
}
