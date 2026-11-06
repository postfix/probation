// Positive control: the required admission call is missing.
mod service_policy {
    fn require_live_service_scope() -> Result<(), ()> { Ok(()) }
    fn load_policy_snapshot() {}
    pub fn snapshot() -> Result<(), ()> {
        load_policy_snapshot();
        Ok(())
    }
}
fn main() {}
