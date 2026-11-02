//! The selected registry identity is the namespace of every persisted project read.

use crate::policy::Ecosystem;
use crate::store::rows::{ProjectRow, ReferenceRow};
use crate::store::{StoreError, StoreHandle, StoreResult};

struct RegistryIdentity<'a> {
    registry: u64,
    ecosystem: Ecosystem,
    package: &'a str,
}

fn check_selected_registry_identity<'a>(
    registry: u64,
    package: &'a str,
    reference: Option<&ReferenceRow>,
) -> StoreResult<RegistryIdentity<'a>> {
    if registry > i64::MAX as u64 || package.is_empty() {
        return Err(StoreError::Corrupt("invalid selected registry identity".to_owned()));
    }
    if let Some(reference) = reference {
        if reference.registry_id != registry || reference.reference.name != package
            || reference.id != crate::artifacts::reference::ReferenceId::compute_in_registry(registry, &reference.reference) {
            return Err(StoreError::Corrupt("reference belongs to another registry".to_owned()));
        }
        return Ok(RegistryIdentity { registry, ecosystem: reference.reference.ecosystem, package });
    }
    Ok(RegistryIdentity { registry, ecosystem: Ecosystem::Npm, package })
}

async fn use_registry_persisted_state(
    store: &StoreHandle,
    identity: RegistryIdentity<'_>,
) -> StoreResult<Option<ProjectRow>> {
    let row = store.get_project_in(identity.registry, identity.ecosystem, identity.package).await?;
    if row.as_ref().is_some_and(|row| row.ecosystem != identity.ecosystem || row.name != identity.package) {
        return Err(StoreError::Corrupt("project row does not match selected registry".to_owned()));
    }
    Ok(row)
}

/// Ordered source obligation plus a live, exact namespace check before the read.
pub async fn apply_registry_state(
    store: &StoreHandle,
    registry: u64,
    package: &str,
    reference: Option<&ReferenceRow>,
) -> StoreResult<Option<ProjectRow>> {
    let identity = check_selected_registry_identity(registry, package, reference)?;
    use_registry_persisted_state(store, identity).await
}
