// Proposed async source shape only. The analyzer checks call dominance.
mod service_policy {
    async fn require_live_service_scope() -> Result<(), ()> { Ok(()) }
    async fn load_policy_snapshot() {}
    pub async fn snapshot() -> Result<(), ()> {
        require_live_service_scope().await?;
        load_policy_snapshot().await;
        Ok(())
    }
}
fn main() {}
