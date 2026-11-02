fn unchecked_registry_identity(registry: u64) -> u64 {
    registry
}

fn use_registry_persisted_state(_identity: u64) {}

pub fn apply_registry_state(registry: u64) {
    let identity = unchecked_registry_identity(registry);
    use_registry_persisted_state(identity);
}
