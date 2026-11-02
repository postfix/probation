//! Durable, member-bound npm unpublish references. The store task serializes quota and marker changes.

use turso::{Connection, Value};
use std::collections::HashSet;

use super::rows::{ReferenceId, integer, text};
use super::{StoreError, StoreResult, settle};

#[derive(Clone, Debug)]
pub struct ActionLease {
    pub registry_id: u64,
    pub member_id: u32,
    pub reference_id: ReferenceId,
    pub package: String,
    pub version: String,
    pub filename: String,
    pub sealed_url: Vec<u8>,
    pub expires_at_micros: i64,
}

#[derive(Clone, Copy)]
struct LeaseLimits { member: i64, registry: i64, global: i64 }

const PRODUCTION_LIMITS: LeaseLimits = LeaseLimits { member: 20_000, registry: 100_000, global: 1_000_000 };

pub async fn commit(connection: &mut Connection, registry_id: u64, member_id: u32, package: &str, leases: &[ActionLease], now: i64) -> StoreResult<()> {
    commit_with_limits(connection, registry_id, member_id, package, leases, now, PRODUCTION_LIMITS).await
}

async fn commit_with_limits(connection: &mut Connection, registry_id: u64, member_id: u32, package: &str, leases: &[ActionLease], now: i64, limits: LeaseLimits) -> StoreResult<()> {
    let tx = connection.transaction().await?;
    let result = async {
        tx.execute("DELETE FROM npm_unpublish_leases WHERE expires_at_micros <= ?1", (now,)).await?;
        if leases.iter().any(|lease| lease.registry_id != registry_id || lease.member_id != member_id || lease.package != package) {
            return Err(StoreError::Corrupt("mixed action lease batch".into()));
        }
        let listed: HashSet<_> = leases.iter().map(|lease| lease.reference_id).collect();
        let mut rows = tx.query("SELECT reference_id FROM npm_unpublish_leases WHERE registry_id = ?1 AND member_id = ?2 AND package = ?3 AND accepted_revision IS NULL",
            (registry_id as i64, member_id as i64, package)).await?;
        let mut stale = Vec::new();
        while let Some(row) = rows.next().await? {
            let id = match row.get_value(0) { Ok(Value::Blob(value)) if value.len() == 32 => ReferenceId::from_bytes(value.try_into().expect("checked length")), _ => return Err(StoreError::Corrupt("lease reference ID is invalid".into())) };
            if !listed.contains(&id) { stale.push(id); }
        }
        drop(rows);
        for id in stale {
            tx.execute("DELETE FROM npm_unpublish_leases WHERE registry_id = ?1 AND member_id = ?2 AND reference_id = ?3 AND accepted_revision IS NULL",
                (registry_id as i64, member_id as i64, id.as_bytes().to_vec())).await?;
        }
        for lease in leases {
            let mut existing = tx.query(
                "SELECT sealed_url FROM npm_unpublish_leases WHERE registry_id = ?1 AND member_id = ?2 AND reference_id = ?3",
                (lease.registry_id as i64, lease.member_id as i64, lease.reference_id.as_bytes().to_vec()),
            ).await?;
            if existing.next().await?.is_some() {
                drop(existing);
                tx.execute("UPDATE npm_unpublish_leases SET sealed_url = ?1, expires_at_micros = ?2 WHERE registry_id = ?3 AND member_id = ?4 AND reference_id = ?5 AND accepted_revision IS NULL",
                    (lease.sealed_url.clone(), lease.expires_at_micros, lease.registry_id as i64, lease.member_id as i64, lease.reference_id.as_bytes().to_vec())).await?;
                continue;
            }
            drop(existing);
            for (query, limit) in [
                ("SELECT count(*) FROM npm_unpublish_leases WHERE member_id = ?1", limits.member),
                ("SELECT count(*) FROM npm_unpublish_leases WHERE registry_id = ?1", limits.registry),
                ("SELECT count(*) FROM npm_unpublish_leases", limits.global),
            ] {
                let count = if query.contains("member_id") {
                    let mut rows = tx.query(query, (lease.member_id as i64,)).await?;
                    integer(&rows.next().await?.ok_or_else(|| StoreError::Corrupt("missing lease count".into()))?, 0, "lease count")?
                } else if query.contains("registry_id") {
                    let mut rows = tx.query(query, (lease.registry_id as i64,)).await?;
                    integer(&rows.next().await?.ok_or_else(|| StoreError::Corrupt("missing lease count".into()))?, 0, "lease count")?
                } else {
                    let mut rows = tx.query(query, ()).await?;
                    integer(&rows.next().await?.ok_or_else(|| StoreError::Corrupt("missing lease count".into()))?, 0, "lease count")?
                };
                if count >= limit { return Err(StoreError::Busy); }
            }
            tx.execute("INSERT INTO npm_unpublish_leases (registry_id, member_id, reference_id, package, version, filename, sealed_url, expires_at_micros) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                (lease.registry_id as i64, lease.member_id as i64, lease.reference_id.as_bytes().to_vec(), lease.package.as_str(), lease.version.as_str(), lease.filename.as_str(), lease.sealed_url.clone(), lease.expires_at_micros)).await?;
        }
        Ok(())
    }.await;
    settle(tx, result).await
}

pub async fn get(connection: &mut Connection, registry_id: u64, member_id: u32, id: ReferenceId, now: i64) -> StoreResult<Option<ActionLease>> {
    let mut rows = connection.query("SELECT package, version, filename, sealed_url, expires_at_micros FROM npm_unpublish_leases WHERE registry_id = ?1 AND member_id = ?2 AND reference_id = ?3 AND expires_at_micros > ?4",
        (registry_id as i64, member_id as i64, id.as_bytes().to_vec(), now)).await?;
    let Some(row) = rows.next().await? else { return Ok(None); };
    let sealed_url = match row.get_value(3) { Ok(Value::Blob(value)) => value, _ => return Err(StoreError::Corrupt("lease URL is not sealed bytes".into())) };
    Ok(Some(ActionLease { registry_id, member_id, reference_id: id, package: text(&row, 0, "lease package")?, version: text(&row, 1, "lease version")?, filename: text(&row, 2, "lease filename")?, sealed_url, expires_at_micros: integer(&row, 4, "lease expiry")? }))
}

pub async fn list_package(connection: &mut Connection, registry_id: u64, member_id: u32, package: &str, now: i64) -> StoreResult<Vec<ActionLease>> {
    let mut rows = connection.query("SELECT reference_id, version, filename, sealed_url, expires_at_micros FROM npm_unpublish_leases WHERE registry_id = ?1 AND member_id = ?2 AND package = ?3 AND expires_at_micros > ?4 AND consumed = 0 AND accepted_revision IS NULL",
        (registry_id as i64, member_id as i64, package, now)).await?;
    let mut leases = Vec::new();
    while let Some(row) = rows.next().await? {
        let id = match row.get_value(0) { Ok(Value::Blob(value)) if value.len() == 32 => ReferenceId::from_bytes(value.try_into().expect("checked length")), _ => return Err(StoreError::Corrupt("lease reference ID is invalid".into())) };
        let sealed_url = match row.get_value(3) { Ok(Value::Blob(value)) => value, _ => return Err(StoreError::Corrupt("lease URL is not sealed bytes".into())) };
        leases.push(ActionLease { registry_id, member_id, reference_id: id, package: package.to_owned(), version: text(&row, 1, "lease version")?, filename: text(&row, 2, "lease filename")?, sealed_url, expires_at_micros: integer(&row, 4, "lease expiry")? });
    }
    Ok(leases)
}

pub async fn mark_removed(connection: &mut Connection, registry_id: u64, member_id: u32, removed: &[ReferenceId], revision: &str) -> StoreResult<()> {
    let tx = connection.transaction().await?;
    let result = async {
        for id in removed {
            let changed = tx.execute("UPDATE npm_unpublish_leases SET accepted_revision = ?1 WHERE registry_id = ?2 AND member_id = ?3 AND reference_id = ?4 AND consumed = 0 AND accepted_revision IS NULL",
                (revision, registry_id as i64, member_id as i64, id.as_bytes().to_vec())).await?;
            if changed != 1 { return Err(StoreError::Corrupt("removed version lease disappeared".into())); }
        }
        Ok(())
    }.await;
    settle(tx, result).await
}

pub async fn consume_marker(connection: &mut Connection, registry_id: u64, member_id: u32, id: ReferenceId, revision: &str, now: i64) -> StoreResult<bool> {
    let changed = connection.execute("UPDATE npm_unpublish_leases SET consumed = 1 WHERE registry_id = ?1 AND member_id = ?2 AND reference_id = ?3 AND accepted_revision = ?4 AND expires_at_micros > ?5 AND consumed = 0",
        (registry_id as i64, member_id as i64, id.as_bytes().to_vec(), revision, now)).await?;
    Ok(changed == 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::startup;

    fn lease(registry_id: u64, member_id: u32, byte: u8) -> ActionLease {
        ActionLease { registry_id, member_id, reference_id: ReferenceId::from_bytes([byte; 32]),
            package: "quota-test".into(), version: format!("{byte}.0.0"), filename: format!("quota-test-{byte}.tgz"),
            sealed_url: vec![byte], expires_at_micros: 1000 }
    }

    fn distinct_lease(registry_id: u64, member_id: u32, byte: u8) -> ActionLease {
        let mut value = lease(registry_id, member_id, byte);
        value.package = format!("quota-test-{byte}");
        value
    }

    #[tokio::test]
    async fn seeded_store_quota_refuses_batch_without_partial_links() {
        let dir = tempfile::tempdir().expect("disk-backed test directory");
        let opened = startup::open_and_recover(dir.path()).await.expect("open store");
        let mut connection = opened.connection.expect("fresh database");
        let limits = LeaseLimits { member: 2, registry: 3, global: 4 };
        commit_with_limits(&mut connection, 1, 10, "quota-test-1", &[distinct_lease(1, 10, 1)], 0, limits).await.expect("first member lease");
        commit_with_limits(&mut connection, 1, 10, "quota-test-2", &[distinct_lease(1, 10, 2)], 0, limits).await.expect("seed member quota");
        let refused = commit_with_limits(&mut connection, 1, 10, "quota-test-3", &[distinct_lease(1, 10, 3)], 0, limits).await;
        assert!(matches!(refused, Err(StoreError::Busy)), "member quota+1 must refuse");
        assert!(get(&mut connection, 1, 10, ReferenceId::from_bytes([1; 32]), 0).await.unwrap().is_some());
        assert!(get(&mut connection, 1, 10, ReferenceId::from_bytes([3; 32]), 0).await.unwrap().is_none());
        commit_with_limits(&mut connection, 1, 11, "quota-test-4", &[distinct_lease(1, 11, 4)], 0, limits).await.expect("seed registry quota");
        assert!(matches!(commit_with_limits(&mut connection, 1, 12, "quota-test-5", &[distinct_lease(1, 12, 5)], 0, limits).await, Err(StoreError::Busy)), "registry quota+1");
        commit_with_limits(&mut connection, 2, 12, "quota-test-6", &[distinct_lease(2, 12, 6)], 0, limits).await.expect("seed global quota");
        assert!(matches!(commit_with_limits(&mut connection, 3, 13, "quota-test-7", &[distinct_lease(3, 13, 7)], 0, limits).await, Err(StoreError::Busy)), "global quota+1");
        let mut rows = connection.query("SELECT count(*) FROM npm_unpublish_leases", ()).await.unwrap();
        assert_eq!(integer(&rows.next().await.unwrap().unwrap(), 0, "lease count").unwrap(), 4);
    }

    #[tokio::test]
    async fn accepted_removal_is_not_reclassified_by_a_later_revision_put() {
        let dir = tempfile::tempdir().expect("disk-backed test directory");
        let opened = startup::open_and_recover(dir.path()).await.expect("open store");
        let mut connection = opened.connection.expect("fresh database");
        commit(&mut connection, 1, 10, "quota-test", &[lease(1, 10, 1), lease(1, 10, 2)], 0).await.unwrap();
        mark_removed(&mut connection, 1, 10, &[ReferenceId::from_bytes([1; 32])], "2").await.unwrap();
        let candidates = list_package(&mut connection, 1, 10, "quota-test", 0).await.unwrap();
        assert_eq!(candidates.len(), 1, "already marked version cannot be marked by another PUT");
        assert_eq!(candidates[0].version, "2.0.0");
        assert!(consume_marker(&mut connection, 1, 10, ReferenceId::from_bytes([1; 32]), "2", 0).await.unwrap());
        assert!(!consume_marker(&mut connection, 1, 10, ReferenceId::from_bytes([1; 32]), "3", 0).await.unwrap());
    }

    #[tokio::test]
    async fn same_reference_is_member_bound_and_expires_at_lease_boundary() {
        let dir = tempfile::tempdir().expect("disk-backed test directory");
        let opened = startup::open_and_recover(dir.path()).await.expect("open store");
        let mut connection = opened.connection.expect("fresh database");
        let id = ReferenceId::from_bytes([1; 32]);
        commit(&mut connection, 1, 10, "quota-test", &[lease(1, 10, 1)], 0).await.unwrap();
        commit(&mut connection, 1, 11, "quota-test", &[lease(1, 11, 1)], 0).await.unwrap();
        assert!(get(&mut connection, 1, 10, id, 999).await.unwrap().is_some());
        assert!(get(&mut connection, 1, 11, id, 999).await.unwrap().is_some());
        assert!(get(&mut connection, 1, 10, id, 1000).await.unwrap().is_none(), "lease expires exactly at its boundary");
        mark_removed(&mut connection, 1, 10, &[id], "2").await.unwrap();
        assert!(!consume_marker(&mut connection, 1, 11, id, "2", 999).await.unwrap(),
            "second member cannot consume another member's marker");
        assert!(!consume_marker(&mut connection, 1, 10, id, "2", 1000).await.unwrap(),
            "expired marker cannot send even for its member");
        assert!(consume_marker(&mut connection, 1, 10, id, "2", 999).await.unwrap());
        assert!(!consume_marker(&mut connection, 1, 10, id, "2", 999).await.unwrap(), "marker is one-use");
    }

    #[tokio::test]
    async fn marker_commit_rejects_a_disappeared_lease_atomically() {
        let dir = tempfile::tempdir().expect("disk-backed test directory");
        let opened = startup::open_and_recover(dir.path()).await.expect("open store");
        let mut connection = opened.connection.expect("fresh database");
        let first = ReferenceId::from_bytes([1; 32]);
        let missing = ReferenceId::from_bytes([2; 32]);
        commit(&mut connection, 1, 10, "quota-test", &[lease(1, 10, 1)], 0).await.unwrap();
        let failed = mark_removed(&mut connection, 1, 10, &[first, missing], "2").await;
        assert!(matches!(failed, Err(StoreError::Corrupt(_))), "accepted PUT marker cannot silently omit a lease");
        assert!(!consume_marker(&mut connection, 1, 10, first, "2", 0).await.unwrap(),
            "marker transaction rolls back earlier updates when one lease disappeared");
    }

    #[tokio::test]
    async fn empty_relisting_prunes_unaccepted_version_before_revision_put() {
        let dir = tempfile::tempdir().expect("disk-backed test directory");
        let opened = startup::open_and_recover(dir.path()).await.expect("open store");
        let mut connection = opened.connection.expect("fresh database");
        commit(&mut connection, 1, 10, "quota-test", &[lease(1, 10, 1)], 0).await.unwrap();
        commit(&mut connection, 1, 10, "quota-test", &[], 1).await.unwrap();
        assert!(list_package(&mut connection, 1, 10, "quota-test", 1).await.unwrap().is_empty(),
            "an empty upstream listing revokes an unaccepted stale lease");
        assert!(matches!(mark_removed(&mut connection, 1, 10, &[ReferenceId::from_bytes([1; 32])], "2").await,
            Err(StoreError::Corrupt(_))), "later accepted empty PUT cannot create a marker for the old version");
        assert!(!consume_marker(&mut connection, 1, 10, ReferenceId::from_bytes([1; 32]), "2", 1).await.unwrap(),
            "old reference cannot send a DELETE");
    }

    #[tokio::test]
    async fn stale_relisting_keeps_accepted_removal_until_delete() {
        let dir = tempfile::tempdir().expect("disk-backed test directory");
        let opened = startup::open_and_recover(dir.path()).await.expect("open store");
        let mut connection = opened.connection.expect("fresh database");
        let first = ReferenceId::from_bytes([1; 32]);
        commit(&mut connection, 1, 10, "quota-test", &[lease(1, 10, 1), lease(1, 10, 2)], 0).await.unwrap();
        mark_removed(&mut connection, 1, 10, &[first], "2").await.unwrap();
        commit(&mut connection, 1, 10, "quota-test", &[lease(1, 10, 1), lease(1, 10, 2)], 1).await.unwrap();
        assert!(consume_marker(&mut connection, 1, 10, first, "2", 1).await.unwrap(),
            "a stale preflight cannot erase the accepted removal marker");
        assert!(!consume_marker(&mut connection, 1, 10, first, "2", 1).await.unwrap(),
            "the preserved marker still permits exactly one DELETE");
    }
}
