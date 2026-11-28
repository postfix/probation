//! Small synchronous guards the async operations call in a fixed order, so the order is
//! a property of one lowerable function rather than of an `await` sequence (03 § Order
//! guards). That the async code calls each guard first remains a runtime and review
//! obligation.

use probation_policy::api::ServicePolicySnapshot;

use super::service_policy::{ActiveRevision, ServicePolicyError};
use crate::http::service_connector::Denylist;

/// Structural checks of a received snapshot, in order: shape and bounds (including the
/// descriptor denylist), then the monotonic revision floor. Any failure retains the last
/// good snapshot and never creates or clears a refusal. Runs before persistence and
/// before the publication gate is taken.
pub(super) fn activation_order(
    reply: &ServicePolicySnapshot,
    deny: &Denylist,
    floor: Option<&ActiveRevision>,
) -> Result<(), ServicePolicyError> {
    super::service_policy::validate(reply, deny)?;
    match floor {
        Some(floor) if !floor.admits(reply) => Err(ServicePolicyError),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape check runs before the floor check: an invalid snapshot is refused even
    /// when the floor would admit it, and a valid older revision is refused by the floor.
    #[test]
    fn activation_order_checks_shape_then_floor() {
        let mut snapshot = ServicePolicySnapshot {
            version: 1,
            key_id: probation_policy::api::KeyId(7),
            org: probation_policy::api::OrgId(10),
            account: probation_policy::PlaceRef {
                kind: probation_policy::LayerKind::Org,
                id: 10,
            },
            revision: 5,
            place_chain: Vec::new(),
            layers: Vec::new(),
            rate_limit: None,
            rate_limit_source: probation_policy::api::LimitSource::Default,
            registries: Vec::new(),
        };
        let deny = Denylist::default();
        assert!(
            activation_order(&snapshot, &deny, None).is_err(),
            "no chain: invalid shape"
        );
        let floor = ActiveRevision::of(&snapshot);
        snapshot.revision = 4;
        assert!(activation_order(&snapshot, &deny, Some(&floor)).is_err());
    }
}
