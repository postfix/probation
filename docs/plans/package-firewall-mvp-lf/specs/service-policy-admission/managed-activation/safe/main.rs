// Proposed source shape only. The analyzer checks call dominance.
mod service_policy {
    fn validate_policy_snapshot() -> Result<(), ()> { Ok(()) }
    fn publish_policy_snapshot() {}
    pub fn activate() -> Result<(), ()> {
        validate_policy_snapshot()?;
        publish_policy_snapshot();
        Ok(())
    }
}
fn main() {}
