// Positive control: the required authorization call is missing.
mod service_registry {
    fn authorize_current_policy() -> Result<(), ()> { Ok(()) }
    fn release_verified_response() {}
    pub fn respond() -> Result<(), ()> {
        release_verified_response();
        Ok(())
    }
}
fn main() {}
