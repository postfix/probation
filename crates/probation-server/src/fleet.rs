//! The firewall fleet (C22, C69–C72): registration (each firewall gets one `fwt_` token,
//! usable only from its `allowed_source_cidrs`, T31), settings pushed in staged
//! rollouts, retirement, and each firewall's health from its reports.

use ipnet::IpNet;
use probation_policy::LOCAL_ONLY_SETTINGS;
use probation_policy::api::{FirewallReport, Reachability};
use sqlx::{PgConnection, PgPool};

use crate::audit;
use crate::keys::{self, KeyKind};
use crate::sync::{ChangeKind, record_change};
use crate::tenancy::{Actor, ChangeError, PLATFORM, Role};

/// A registered firewall. The token is shown once.
pub struct Registered {
    pub id: i32,
    pub token: String,
}

#[derive(Debug)]
pub enum RegisterError {
    /// Only a global admin registers firewalls (C4).
    Denied,
    Store(sqlx::Error),
}

impl From<sqlx::Error> for RegisterError {
    fn from(err: sqlx::Error) -> Self {
        RegisterError::Store(err)
    }
}

/// Registers a firewall with its audit row, in one transaction.
pub async fn register(
    pool: &PgPool,
    actor: &Actor,
    name: &str,
    allowed_source_cidrs: &[IpNet],
) -> Result<Registered, RegisterError> {
    if !actor.is_global_admin() {
        return Err(RegisterError::Denied);
    }
    let mut tx = pool.begin().await?;
    let firewall = insert(&mut tx, name, allowed_source_cidrs).await?;
    let sources: Vec<String> = allowed_source_cidrs.iter().map(IpNet::to_string).collect();
    let () = audit::record(
        &mut tx,
        audit::Entry {
            actor,
            org_id: None,
            action: "firewall.register",
            subject: format!("firewall:{}", firewall.id),
            before: None,
            after: Some(serde_json::json!({"name": name, "allowed_source_cidrs": sources})),
        },
    )
    .await?;
    let () = tx.commit().await?;
    Ok(firewall)
}

/// The firewall row and its token, without an audit row: the caller writes one.
pub(crate) async fn insert(
    conn: &mut PgConnection,
    name: &str,
    allowed_source_cidrs: &[IpNet],
) -> Result<Registered, sqlx::Error> {
    let token = keys::insert(conn, KeyKind::Firewall, PLATFORM, None, name).await?;
    let id = sqlx::query_scalar(
        "INSERT INTO firewalls (name, token_key_id, allowed_source_cidrs) VALUES ($1, $2, $3::inet[]::cidr[]) RETURNING id",
    )
    .bind(name)
    .bind(token.id.0 as i64)
    .bind(allowed_source_cidrs)
    .fetch_one(conn)
    .await?;
    Ok(Registered {
        id,
        token: token.secret,
    })
}

fn global_admin(actor: &Actor) -> Result<(), ChangeError> {
    if actor.role(PLATFORM) == Some(Role::GlobalAdmin) {
        Ok(())
    } else {
        Err(ChangeError::Denied)
    }
}

/// Retires firewall `id` once its name is typed (C72): its token is revoked, so its next
/// check-in answers 401 and it stops serving every request; a `firewall` row records
/// it. Its waiting step in a running rollout is skipped.
pub async fn retire(
    pool: &PgPool,
    actor: &Actor,
    id: i32,
    confirm: &str,
) -> Result<(), ChangeError> {
    global_admin(actor)?;
    let mut tx = pool.begin().await?;
    let found: Option<(String, i64)> = sqlx::query_as(
        "SELECT name, token_key_id FROM firewalls WHERE id = $1 AND retired_at IS NULL FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((name, token)) = found else {
        return Err(ChangeError::NotFound);
    };
    if confirm.trim() != name {
        return Err(ChangeError::Refused(format!(
            "Not retired. Type {name} to confirm."
        )));
    }
    sqlx::query("UPDATE firewalls SET retired_at = now() WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE keys SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL")
        .bind(token)
        .execute(&mut *tx)
        .await?;
    record_change(&mut tx, ChangeKind::Firewall, &id).await?;
    let waiting: Vec<i32> = sqlx::query_scalar(
        "UPDATE settings_rollout_steps AS s SET state = 'skipped', done_at = now()
         FROM settings_rollouts AS r
         WHERE r.id = s.rollout_id AND r.state = 'running' AND s.firewall_id = $1 AND s.state = 'sent'
         RETURNING s.rollout_id",
    )
    .bind(id)
    .fetch_all(&mut *tx)
    .await?;
    for rollout in waiting {
        release_next(&mut tx, rollout, true).await?;
    }
    let () = audit::record(
        &mut tx,
        audit::Entry {
            actor,
            org_id: None,
            action: "firewall.retire",
            subject: format!("firewall:{id}"),
            before: Some(serde_json::json!({"name": name, "retired": false})),
            after: Some(serde_json::json!({"name": name, "retired": true})),
        },
    )
    .await?;
    let () = tx.commit().await?;
    Ok(())
}

/// The firewall's own check of a push, made here first so that a push it would refuse is
/// never stored: TOML, no local-only setting (C35, C118, T5), `https` upstreams. Start-up
/// validation and path confinement stay on the firewall, which knows its `data_dir`.
pub fn check_settings(text: &str) -> Result<(), String> {
    let table: toml::Table = toml::from_str(text)
        .map_err(|err| format!("Not saved: the settings are not TOML: {err}"))?;
    if let Some(key) = table
        .keys()
        .find(|key| LOCAL_ONLY_SETTINGS.contains(&key.as_str()))
    {
        return Err(format!(
            "Not saved: `{key}` is set on each firewall only and cannot be pushed."
        ));
    }
    for key in [
        "npm_upstream_url",
        "pypi_upstream_url",
        "pypi_artifacts_url",
    ] {
        if table
            .get(key)
            .is_some_and(|url| !url.as_str().is_some_and(|url| url.starts_with("https://")))
        {
            return Err(format!("Not saved: `{key}` must be an https:// address."));
        }
    }
    Ok(())
}

/// Saves `text` as the settings of `firewalls`, applied one at a time in that order
/// (C70): the first gets them now, each next one after the one before reports success.
/// Returns the rollout; its id is the settings revision each firewall reports back.
pub async fn push_settings(
    pool: &PgPool,
    actor: &Actor,
    firewalls: &[i32],
    text: &str,
) -> Result<i32, ChangeError> {
    global_admin(actor)?;
    check_settings(text).map_err(ChangeError::Refused)?;
    if firewalls.is_empty() {
        return Err(ChangeError::Refused(
            "Not saved: select at least one firewall.".to_owned(),
        ));
    }
    let mut distinct = firewalls.to_vec();
    distinct.sort_unstable();
    distinct.dedup();
    let mut tx = pool.begin().await?;
    // The firewalls' rows are locked, so two pushes to one firewall take turns.
    let live: Vec<i32> = sqlx::query_scalar(
        "SELECT id FROM firewalls WHERE id = ANY($1) AND retired_at IS NULL ORDER BY id FOR UPDATE",
    )
    .bind(firewalls)
    .fetch_all(&mut *tx)
    .await?;
    if live.len() != firewalls.len() || distinct.len() != firewalls.len() {
        return Err(ChangeError::NotFound);
    }
    // A firewall waiting in an unfinished rollout would take this one's revision and
    // never report the older one, so the older would time out (M2).
    let busy: Option<(String, i32)> = sqlx::query_as(
        "SELECT f.name, s.rollout_id FROM settings_rollout_steps AS s
         JOIN settings_rollouts AS r ON r.id = s.rollout_id AND r.state IN ('running', 'halted')
         JOIN firewalls AS f ON f.id = s.firewall_id
         WHERE s.firewall_id = ANY($1) AND s.state IN ('pending', 'sent')
         ORDER BY s.rollout_id LIMIT 1",
    )
    .bind(firewalls)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some((name, rollout)) = busy {
        return Err(ChangeError::Refused(format!(
            "Not saved: {name} is still in rollout {rollout}; finish, skip or resume it first."
        )));
    }
    let rollout: i32 = sqlx::query_scalar(
        "INSERT INTO settings_rollouts (created_by, settings_toml, state) VALUES ($1, $2, 'running') RETURNING id",
    )
    .bind(actor.login_id())
    .bind(text)
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO settings_rollout_steps (rollout_id, firewall_id, position, state)
         SELECT $1, f.firewall, f.position - 1, 'pending'
         FROM unnest($2::integer[]) WITH ORDINALITY AS f(firewall, position)",
    )
    .bind(rollout)
    .bind(firewalls)
    .execute(&mut *tx)
    .await?;
    release_next(&mut tx, rollout, true).await?;
    let () = audit::record(
        &mut tx,
        audit::Entry {
            actor,
            org_id: None,
            action: "firewall.settings",
            subject: format!("rollout:{rollout}"),
            before: None,
            after: Some(serde_json::json!({"firewalls": firewalls, "settings": text})),
        },
    )
    .await?;
    let () = tx.commit().await?;
    Ok(rollout)
}

/// Sends the rollout's settings to its next pending firewall, skipping retired ones, or
/// marks the rollout done. The firewall gets them in its next `changes` answer, as their
/// revision differs from the one it reports (C105). `log` writes the `settings` row; the
/// `changes` transaction passes false, because a `changes` request never moves the
/// server's revision (C126).
async fn release_next(conn: &mut PgConnection, rollout: i32, log: bool) -> Result<(), sqlx::Error> {
    loop {
        let next: Option<i32> = sqlx::query_scalar(
            "SELECT firewall_id FROM settings_rollout_steps
             WHERE rollout_id = $1 AND state = 'pending' ORDER BY position LIMIT 1",
        )
        .bind(rollout)
        .fetch_optional(&mut *conn)
        .await?;
        let Some(firewall) = next else {
            sqlx::query("UPDATE settings_rollouts SET state = 'done' WHERE id = $1")
                .bind(rollout)
                .execute(&mut *conn)
                .await?;
            return Ok(());
        };
        let sent = sqlx::query(
            "UPDATE firewalls SET settings_revision = $1,
                 settings_toml = (SELECT settings_toml FROM settings_rollouts WHERE id = $1)
             WHERE id = $2 AND retired_at IS NULL",
        )
        .bind(rollout)
        .bind(firewall)
        .execute(&mut *conn)
        .await?
        .rows_affected()
            == 1;
        sqlx::query(
            "UPDATE settings_rollout_steps
             SET state = CASE WHEN $3 THEN 'sent' ELSE 'skipped' END,
                 sent_at = CASE WHEN $3 THEN now() END,
                 done_at = CASE WHEN $3 THEN NULL ELSE now() END
             WHERE rollout_id = $1 AND firewall_id = $2",
        )
        .bind(rollout)
        .bind(firewall)
        .bind(sent)
        .execute(&mut *conn)
        .await?;
        if sent {
            if log {
                record_change(conn, ChangeKind::Settings, &firewall).await?;
            }
            return Ok(());
        }
    }
}

/// A firewall's check-in, in the `changes` transaction that records it and before its
/// `last_seen_at` moves. Its step of a running rollout succeeded when it reports the
/// rollout's revision, which releases the next step under the rollout's lock (C70); it
/// failed when the firewall reports an error after it was answered with the push (C71),
/// which halts the rollout.
pub(crate) async fn settle(
    conn: &mut PgConnection,
    firewall: i32,
    report: &FirewallReport,
) -> Result<(), sqlx::Error> {
    let step: Option<(i32, bool)> = sqlx::query_as(
        "SELECT s.rollout_id, COALESCE(f.last_seen_at > s.sent_at, false)
         FROM settings_rollout_steps AS s
         JOIN settings_rollouts AS r ON r.id = s.rollout_id AND r.state = 'running'
         JOIN firewalls AS f ON f.id = s.firewall_id
         WHERE s.firewall_id = $1 AND s.state = 'sent'
         ORDER BY s.rollout_id LIMIT 1
         FOR UPDATE OF r, s",
    )
    .bind(firewall)
    .fetch_optional(&mut *conn)
    .await?;
    let Some((rollout, answered)) = step else {
        return Ok(());
    };
    if report.settings_revision == rollout as u64 {
        sqlx::query(
            "UPDATE settings_rollout_steps SET state = 'applied', done_at = now()
             WHERE rollout_id = $1 AND firewall_id = $2",
        )
        .bind(rollout)
        .bind(firewall)
        .execute(&mut *conn)
        .await?;
        return release_next(conn, rollout, false).await;
    }
    if let (true, Some(error)) = (answered, &report.last_apply_error) {
        sqlx::query(
            "UPDATE settings_rollout_steps SET state = 'failed', done_at = now(), error = $3
             WHERE rollout_id = $1 AND firewall_id = $2",
        )
        .bind(rollout)
        .bind(firewall)
        .bind(error)
        .execute(&mut *conn)
        .await?;
        sqlx::query("UPDATE settings_rollouts SET state = 'halted' WHERE id = $1")
            .bind(rollout)
            .execute(&mut *conn)
            .await?;
    }
    Ok(())
}

/// Halts each running rollout whose released step has not reported success within 3 of
/// its firewall's intervals (C71), the reported period taken as 1 s to 1 day, as
/// `health` takes it.
// ponytail: run when the fleet page is read, not by a job; the next firewall gets
// nothing either way, so only the stored state waits for a reader.
async fn expire(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "WITH late AS (
             UPDATE settings_rollout_steps AS s SET state = 'timed_out', done_at = now()
             FROM settings_rollouts AS r, firewalls AS f
             WHERE r.id = s.rollout_id AND r.state = 'running' AND f.id = s.firewall_id
               AND s.state = 'sent'
               AND s.sent_at < now() - make_interval(secs => 3 * LEAST(86400, GREATEST(1, COALESCE(
                       (f.last_report -> 'report' ->> 'effective_period_seconds')::double precision, 60))))
             RETURNING s.rollout_id
         )
         UPDATE settings_rollouts SET state = 'halted' WHERE id IN (SELECT rollout_id FROM late)",
    )
    .execute(pool)
    .await
    .map(drop)
}

/// "Resume" on a rollout halted by a step that timed out: it is sent again (C71). A
/// failed step is never resumed: the firewall does not apply a revision it refused
/// again, so the operator skips it and pushes new settings.
pub async fn resume(pool: &PgPool, actor: &Actor, rollout: i32) -> Result<(), ChangeError> {
    unhalt(pool, actor, rollout, false).await
}

/// "Skip" on a halted rollout: its stopped step is skipped and the next firewall gets
/// the settings (C71).
pub async fn skip(pool: &PgPool, actor: &Actor, rollout: i32) -> Result<(), ChangeError> {
    unhalt(pool, actor, rollout, true).await
}

async fn unhalt(pool: &PgPool, actor: &Actor, rollout: i32, skip: bool) -> Result<(), ChangeError> {
    global_admin(actor)?;
    let mut tx = pool.begin().await?;
    let stopped: Option<(i32, String)> = sqlx::query_as(
        "SELECT s.firewall_id, s.state FROM settings_rollouts AS r
         JOIN settings_rollout_steps AS s ON s.rollout_id = r.id AND s.state IN ('failed', 'timed_out')
         WHERE r.id = $1 AND r.state = 'halted' AND ($2 OR s.state = 'timed_out')
         ORDER BY s.position DESC LIMIT 1
         FOR UPDATE OF r",
    )
    .bind(rollout)
    .bind(skip)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((firewall, state)) = stopped else {
        return Err(ChangeError::NotFound);
    };
    sqlx::query(
        "UPDATE settings_rollout_steps SET state = $3, error = NULL,
             done_at = CASE WHEN $3 = 'skipped' THEN now() END
         WHERE rollout_id = $1 AND firewall_id = $2",
    )
    .bind(rollout)
    .bind(firewall)
    .bind(if skip { "skipped" } else { "pending" })
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE settings_rollouts SET state = 'running' WHERE id = $1")
        .bind(rollout)
        .execute(&mut *tx)
        .await?;
    release_next(&mut tx, rollout, true).await?;
    let () = audit::record(
        &mut tx,
        audit::Entry {
            actor,
            org_id: None,
            action: if skip {
                "rollout.skip"
            } else {
                "rollout.resume"
            },
            subject: format!("rollout:{rollout}"),
            before: Some(
                serde_json::json!({"state": "halted", "firewall": firewall, "step": state}),
            ),
            after: Some(serde_json::json!({"state": "running"})),
        },
    )
    .await?;
    let () = tx.commit().await?;
    Ok(())
}

/// One firewall as the fleet page lists it.
pub struct FirewallRow {
    pub id: i32,
    pub name: String,
    pub version: Option<String>,
    /// "12 seconds ago", or "never".
    pub last_check_in: String,
    pub healthy: bool,
    /// "Healthy", "Unhealthy: missed 3 check-ins", "Unhealthy: cannot reach OSV", …
    pub health: String,
    /// The last error it reported: a refused push or a rejected batch.
    pub error: Option<String>,
    pub retired: bool,
}

/// Every registered firewall, live ones first, by name, with its health (C69):
/// unhealthy after 3 × its reported period with no check-in, or when it reports npm,
/// PyPI or OSV unreachable.
pub async fn firewalls(pool: &PgPool) -> Result<Vec<FirewallRow>, sqlx::Error> {
    type Row = (i32, String, bool, Option<i64>, Option<serde_json::Value>);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT id, name, retired_at IS NOT NULL,
                extract(epoch FROM now() - last_seen_at)::bigint, last_report -> 'report'
         FROM firewalls ORDER BY retired_at IS NOT NULL, name, id",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, name, retired, since, report)| {
            let report: Option<FirewallReport> =
                report.and_then(|report| serde_json::from_value(report).ok());
            let (healthy, health) = health(retired, since, report.as_ref());
            FirewallRow {
                id,
                name,
                version: report.as_ref().map(|report| report.version.clone()),
                last_check_in: since.map_or_else(|| "never".to_owned(), |since| ago(since.max(0))),
                healthy,
                health,
                error: report.and_then(|report| report.last_apply_error),
                retired,
            }
        })
        .collect())
}

/// The longest sync period a firewall's report is taken at: whatever it says, it is
/// unhealthy after 3 days without a check-in.
const MAX_PERIOD_SECONDS: u64 = 86_400;

fn health(retired: bool, since: Option<i64>, report: Option<&FirewallReport>) -> (bool, String) {
    if retired {
        return (false, "Retired".to_owned());
    }
    let (Some(since), Some(report)) = (since, report) else {
        return (false, "Waiting for its first check-in".to_owned());
    };
    if since > 3 * report.effective_period_seconds.clamp(1, MAX_PERIOD_SECONDS) as i64 {
        return (false, "Unhealthy: missed 3 check-ins".to_owned());
    }
    let upstreams = report.status.upstreams;
    let down: Vec<&str> = [
        (upstreams.npm, "npm"),
        (upstreams.pypi, "PyPI"),
        (upstreams.osv, "OSV"),
    ]
    .into_iter()
    .filter(|(reach, _)| *reach == Reachability::Unreachable)
    .map(|(_, name)| name)
    .collect();
    if down.is_empty() {
        (true, "Healthy".to_owned())
    } else {
        (
            false,
            format!("Unhealthy: cannot reach {}", down.join(", ")),
        )
    }
}

fn ago(seconds: i64) -> String {
    match seconds {
        0..120 => format!("{seconds} seconds ago"),
        120..7200 => format!("{} minutes ago", seconds / 60),
        _ => format!("{} hours ago", seconds / 3600),
    }
}

/// One step of a rollout: the firewall's name, the step's state and the error it
/// reported.
pub struct StepRow {
    pub firewall: String,
    pub state: String,
    pub error: Option<String>,
}

/// One settings rollout as the fleet page shows it.
pub struct RolloutRow {
    pub id: i32,
    pub state: String,
    /// Halted by a step that timed out, so "Resume" may send it again.
    pub resumable: bool,
    pub created: String,
    pub settings: String,
    pub steps: Vec<StepRow>,
}

/// The ten latest rollouts, newest first, after halting those that timed out.
pub async fn rollouts(pool: &PgPool) -> Result<Vec<RolloutRow>, sqlx::Error> {
    expire(pool).await?;
    let rollouts: Vec<(i32, String, String, String)> = sqlx::query_as(
        "SELECT id, state, to_char(created_at, 'DD Mon YYYY HH24:MI'), settings_toml
         FROM settings_rollouts ORDER BY id DESC LIMIT 10",
    )
    .fetch_all(pool)
    .await?;
    let mut rows = Vec::with_capacity(rollouts.len());
    for (id, state, created, settings) in rollouts {
        let steps: Vec<(String, String, Option<String>)> = sqlx::query_as(
            "SELECT f.name, s.state, s.error FROM settings_rollout_steps AS s
             JOIN firewalls AS f ON f.id = s.firewall_id
             WHERE s.rollout_id = $1 ORDER BY s.position",
        )
        .bind(id)
        .fetch_all(pool)
        .await?;
        rows.push(RolloutRow {
            id,
            resumable: state == "halted" && steps.iter().any(|(_, step, _)| step == "timed_out"),
            state,
            created,
            settings,
            steps: steps
                .into_iter()
                .map(|(firewall, state, error)| StepRow {
                    firewall,
                    state,
                    error,
                })
                .collect(),
        });
    }
    Ok(rows)
}
