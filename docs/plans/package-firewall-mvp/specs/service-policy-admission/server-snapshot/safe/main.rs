// Proposed source shape only. The analyzer checks call dominance.
mod service_policy {
    fn require_live_service_scope() -> Result<(), ()> { Ok(()) }
    fn load_policy_snapshot() {}
    pub fn snapshot() -> Result<(), ()> {
        require_live_service_scope()?;
        load_policy_snapshot();
        Ok(())
    }
}
fn main() {}
