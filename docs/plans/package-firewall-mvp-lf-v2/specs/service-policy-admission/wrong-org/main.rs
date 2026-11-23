// Unsafe: caller organisation replaces the scope derived from the accepted key.
struct Key { live: bool, service: bool, organisation: u64 }
struct Scope { organisation: u64 }
fn require_live_service_scope(key: &Key) -> Result<Scope, ()> {
    if !key.live || !key.service { return Err(()); }
    Ok(Scope { organisation: key.organisation })
}
fn load_policy_snapshot(scope: Scope) -> u64 { scope.organisation }
fn policy_snapshot(authenticated_key: &Key, caller_organisation: u64) -> Result<u64, ()> {
    let accepted_scope = require_live_service_scope(authenticated_key)?;
    Ok(load_policy_snapshot(Scope { organisation: caller_organisation }))
}
fn main() {}
