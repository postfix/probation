// Positive control: the required validation call is missing.
mod service_policy {
    fn validate_policy_snapshot() -> Result<(), ()> { Ok(()) }
    fn publish_policy_snapshot() {}
    pub fn activate() -> Result<(), ()> {
        publish_policy_snapshot();
        Ok(())
    }
}
fn main() {}
