// Missing admission; expected order finding at load_policy_snapshot.
struct Key { organisation: u64 }
struct Scope { organisation: u64 }
fn require_live_service_scope(key: &Key) -> Result<Scope, ()> {
    Ok(Scope { organisation: key.organisation })
}
fn load_policy_snapshot(scope: Scope) -> u64 { scope.organisation }
fn policy_snapshot(authenticated_key: &Key) -> Result<u64, ()> {
    Ok(load_policy_snapshot(Scope { organisation: authenticated_key.organisation }))
}
fn main() {}
