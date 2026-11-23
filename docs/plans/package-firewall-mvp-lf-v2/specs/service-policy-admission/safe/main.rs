// Proposed seam only. No production behavior is asserted by this fixture.
struct Key { live: bool, service: bool, organisation: u64 }
struct Scope { organisation: u64 }
fn require_live_service_scope(key: &Key) -> Result<Scope, ()> {
    if !key.live || !key.service { return Err(()); }
    Ok(Scope { organisation: key.organisation })
}
fn load_policy_snapshot(scope: Scope) -> u64 { scope.organisation }
fn policy_snapshot(authenticated_key: &Key) -> Result<u64, ()> {
    let scope = require_live_service_scope(authenticated_key)?;
    Ok(load_policy_snapshot(scope))
}
fn main() {}
