// Proposed source shape only. The analyzer checks call dominance.
mod service_registry {
    fn authorize_current_policy() -> Result<(), ()> { Ok(()) }
    fn release_verified_response() {}
    pub fn respond() -> Result<(), ()> {
        authorize_current_policy()?;
        release_verified_response();
        Ok(())
    }
}
fn main() {}
