// Proposed async source shape only. The analyzer checks call dominance.
mod service_policy {
    async fn validate_policy_snapshot() -> Result<(), ()> { Ok(()) }
    async fn publish_policy_snapshot() {}
    pub async fn activate() -> Result<(), ()> {
        publish_policy_snapshot().await;
        Ok(())
    }
}
fn main() {}
