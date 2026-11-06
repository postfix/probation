// Unsafe: validates a different key from the authenticated key.
struct Key { live: bool, service: bool, organisation: u64 }
struct Scope { organisation: u64 }
fn require_live_service_scope(key: &Key) -> Result<Scope, ()> {
    if !key.live || !key.service { return Err(()); }
    Ok(Scope { organisation: key.organisation })
}
fn load_policy_snapshot(scope: Scope) -> u64 { scope.organisation }
fn policy_snapshot(authenticated_key: &Key, other_key: &Key) -> Result<u64, ()> {
    let scope = require_live_service_scope(other_key)?;
    Ok(load_policy_snapshot(scope))
}
fn main() {}
