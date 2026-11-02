//! Rebuild npm advisory replies from currently visible versions and fixed safe fields.

use std::collections::BTreeMap;

use futures_util::{StreamExt, TryStreamExt, stream};
use nodejs_semver::{Range, Version};
use serde_json::{Value, json};

use crate::http::{error::ApiError, npm_routes};
use crate::store::cache::Representation;
use crate::{App, managed::Principal, npm};

const MAX_LOOKUPS: usize = 1024;
const MAX_CONCURRENT: usize = 16;
const MAX_COMPARISONS: usize = 8192;

#[derive(Clone, Copy)]
pub enum AuditKind {
    Bulk,
    Quick,
}

struct Advisory {
    package: String,
    range: Range,
    severity: &'static str,
}

pub async fn filter_audit_response(
    app: &App,
    principal: &Principal,
    registry: u64,
    kind: AuditKind,
    bytes: &[u8],
    max_bytes: usize,
) -> Result<Vec<u8>, ApiError> {
    if bytes.len() > max_bytes {
        return Err(ApiError::UpstreamInvalid);
    }
    let input: Value = serde_json::from_slice(bytes).map_err(|_| ApiError::UpstreamInvalid)?;
    let advisories = (app, principal, registry, parse_advisories(kind, &input)?);
    let visible = visible_advisories(advisories);
    let visible = visible.await?;
    render_audit_response(kind, visible, max_bytes)
}

fn parse_advisories(kind: AuditKind, input: &Value) -> Result<Vec<Advisory>, ApiError> {
    let root = input.as_object().ok_or(ApiError::UpstreamInvalid)?;
    let mut found = Vec::new();
    match kind {
        AuditKind::Bulk => {
            for (package, items) in root {
                let items = items.as_array().ok_or(ApiError::UpstreamInvalid)?;
                for item in items {
                    found.push(parse_one(package, item)?);
                }
            }
        }
        AuditKind::Quick => {
            // Older quick clients use advisories; npm's empty v2 response uses vulnerabilities.
            if let Some(vulnerabilities) = root.get("vulnerabilities")
                && !vulnerabilities
                    .as_object()
                    .is_some_and(serde_json::Map::is_empty)
            {
                return Err(ApiError::UpstreamInvalid);
            }
            if let Some(items) = root.get("advisories") {
                for item in items.as_object().ok_or(ApiError::UpstreamInvalid)?.values() {
                    let package = item
                        .get("module_name")
                        .and_then(Value::as_str)
                        .ok_or(ApiError::UpstreamInvalid)?;
                    found.push(parse_one(package, item)?);
                }
            } else if !root.contains_key("vulnerabilities") {
                return Err(ApiError::UpstreamInvalid);
            }
        }
    }
    Ok(found)
}

fn parse_one(package: &str, item: &Value) -> Result<Advisory, ApiError> {
    let name = npm_routes::parse_name(package).map_err(|_| ApiError::UpstreamInvalid)?;
    let range = item
        .get("vulnerable_versions")
        .and_then(Value::as_str)
        .ok_or(ApiError::UpstreamInvalid)?;
    let range = Range::parse(range).map_err(|_| ApiError::UpstreamInvalid)?;
    let severity = match item.get("severity").and_then(Value::as_str) {
        Some("info") => "info",
        Some("low") => "low",
        Some("moderate") => "moderate",
        Some("high") => "high",
        Some("critical") => "critical",
        _ => return Err(ApiError::UpstreamInvalid),
    };
    Ok(Advisory {
        package: name.as_str().to_owned(),
        range,
        severity,
    })
}

async fn visible_advisories(
    (app, principal, registry, advisories): (&App, &Principal, u64, Vec<Advisory>),
) -> Result<Vec<(String, Vec<String>, &'static str)>, ApiError> {
    let mut counts = BTreeMap::<String, usize>::new();
    for advisory in &advisories {
        *counts.entry(advisory.package.clone()).or_default() += 1;
    }
    if counts.len() > MAX_LOOKUPS {
        return Err(ApiError::UpstreamInvalid);
    }
    let names: Vec<_> = counts.keys().cloned().collect();
    let (versions, _): (BTreeMap<_, _>, usize) =
        stream::iter(names.into_iter().map(|name| async move {
            let parsed = npm_routes::parse_name(&name).map_err(|_| ApiError::UpstreamInvalid)?;
            let rendered = match npm::serve_registry(
                app,
                principal,
                &parsed,
                Representation::NpmFull,
                registry,
            )
            .await
            {
                Ok(rendered) => rendered,
                Err(ApiError::Blocked { .. }) => return Ok((name, Vec::new())),
                Err(error) => return Err(error),
            };
            let value: Value =
                serde_json::from_slice(&rendered.body).map_err(|_| ApiError::UpstreamInvalid)?;
            let versions = value
                .get("versions")
                .and_then(Value::as_object)
                .ok_or(ApiError::UpstreamInvalid)?;
            Ok((name, versions.keys().cloned().collect::<Vec<_>>()))
        }))
        .buffer_unordered(MAX_CONCURRENT)
        .try_fold(
            (BTreeMap::new(), 0usize),
            |(mut versions, comparisons), (name, listed)| {
                let count = counts[&name];
                async move {
                    let comparisons = comparisons
                        .checked_add(
                            count
                                .checked_mul(listed.len())
                                .ok_or(ApiError::UpstreamInvalid)?,
                        )
                        .ok_or(ApiError::UpstreamInvalid)?;
                    if comparisons > MAX_COMPARISONS {
                        return Err(ApiError::UpstreamInvalid);
                    }
                    versions.insert(name, listed);
                    Ok((versions, comparisons))
                }
            },
        )
        .await?;
    let mut filtered = Vec::new();
    for advisory in advisories {
        let mut affected = Vec::new();
        for version in &versions[&advisory.package] {
            let parsed = Version::parse(version).map_err(|_| ApiError::UpstreamInvalid)?;
            if advisory.range.satisfies(&parsed) {
                affected.push(version.clone());
            }
        }
        if !affected.is_empty() {
            filtered.push((advisory.package, affected, advisory.severity));
        }
    }
    Ok(filtered)
}

fn render_audit_response(
    kind: AuditKind,
    advisories: Vec<(String, Vec<String>, &'static str)>,
    max_bytes: usize,
) -> Result<Vec<u8>, ApiError> {
    let mut bulk: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    let mut quick: BTreeMap<String, Value> = BTreeMap::new();
    for (index, (name, versions, severity)) in advisories.into_iter().enumerate() {
        let id = index + 1;
        let range = versions.join(" || ");
        bulk.entry(name.clone()).or_default().push(json!({
            "id": id, "title": "Vulnerability in visible version", "severity": severity,
            "vulnerable_versions": range,
        }));
        quick.insert(
            id.to_string(),
            json!({
                "id": id, "module_name": name, "title": "Vulnerability in visible version",
                "severity": severity, "vulnerable_versions": range,
            }),
        );
    }
    let value = match kind {
        AuditKind::Bulk => json!(bulk),
        AuditKind::Quick => json!({"advisories": quick}),
    };
    let bytes = serde_json::to_vec(&value).map_err(|_| ApiError::UpstreamInvalid)?;
    if bytes.len() > max_bytes {
        return Err(ApiError::UpstreamInvalid);
    }
    Ok(bytes)
}
