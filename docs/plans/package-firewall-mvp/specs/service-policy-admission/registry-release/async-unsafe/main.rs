// Proposed async source shape only. The analyzer checks call dominance.
mod service_registry {
    async fn authorize_current_policy() -> Result<(), ()> { Ok(()) }
    async fn release_verified_response() {}
    pub async fn respond() -> Result<(), ()> {
        release_verified_response().await;
        Ok(())
    }
}
fn main() {}
