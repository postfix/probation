//! The fleet page (mockup fleet.html): every firewall with its version, last check-in
//! and health (C69), registration with its token shown once (C34), settings pushed to
//! one or several firewalls in a staged rollout with halt, resume and skip (C22, C35,
//! C70, C71), and retirement (C72). Only a global admin's session reaches it; any other
//! answers 404 (C1), and a password session needs its authenticator first (C24).

use askama::Template;
use axum::extract::{Form, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use ipnet::IpNet;
use serde::Deserialize;

use super::admin::operator;
use super::{Shared, SignedIn, Top, not_found, redirect, refused, render, unavailable};
use crate::fleet::{self, FirewallRow, RolloutRow};
use crate::tenancy::ChangeError;

#[derive(Template)]
#[template(path = "fleet.html")]
pub(crate) struct FleetPage {
    pub top: Option<Top>,
    pub title: &'static str,
    pub csrf: String,
    pub firewalls: Vec<FirewallRow>,
    pub rollouts: Vec<RolloutRow>,
    /// A firewall just registered: (name, token), shown once.
    pub registered: Option<(String, String)>,
    pub error: Option<String>,
}

pub(crate) async fn show(State(portal): State<Shared>, headers: HeaderMap) -> Response {
    let signed_in = match portal.signed_in(&headers).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    if let Err(answer) = operator(&portal, &signed_in).await {
        return answer;
    }
    page(&portal, &signed_in, StatusCode::OK, None, None).await
}

async fn page(
    portal: &super::Portal,
    signed_in: &SignedIn,
    status: StatusCode,
    error: Option<String>,
    registered: Option<(String, String)>,
) -> Response {
    let built = async {
        let mut top = signed_in.top(portal).await?;
        top.page = "fleet";
        Ok::<_, sqlx::Error>(FleetPage {
            csrf: top.csrf.clone(),
            top: Some(top),
            title: "Fleet",
            firewalls: fleet::firewalls(&portal.pool).await?,
            rollouts: fleet::rollouts(&portal.pool).await?,
            registered,
            error,
        })
    };
    match built.await {
        Ok(page) => render(status, &page),
        Err(err) => unavailable(err),
    }
}

async fn after(
    portal: &super::Portal,
    signed_in: &SignedIn,
    done: Result<(), ChangeError>,
) -> Response {
    match done {
        Ok(()) => redirect("/fleet"),
        Err(ChangeError::Denied) => refused("Only a global admin can do this."),
        Err(ChangeError::NotFound) => not_found(),
        Err(ChangeError::Refused(reason)) => {
            page(portal, signed_in, StatusCode::CONFLICT, Some(reason), None).await
        }
        Err(ChangeError::Store(err)) => unavailable(err),
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct RegisterForm {
    csrf: String,
    name: String,
    /// The address ranges its token is accepted from, separated by spaces or commas
    /// (T31).
    sources: String,
}

/// "Register firewall": its token is shown once.
pub(crate) async fn register(
    State(portal): State<Shared>,
    headers: HeaderMap,
    Form(form): Form<RegisterForm>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    let actor = match operator(&portal, &signed_in).await {
        Ok(actor) => actor,
        Err(answer) => return answer,
    };
    let name = form.name.trim();
    let sources: Result<Vec<IpNet>, _> = form
        .sources
        .split([' ', ',', '\n'])
        .filter(|range| !range.trim().is_empty())
        .map(|range| range.trim().parse::<IpNet>().map(|range| range.trunc()))
        .collect();
    let problem = match &sources {
        _ if name.is_empty() || name.chars().count() > 100 => {
            Some("Give the firewall a name of at most 100 characters.")
        }
        Ok(sources) if sources.is_empty() => {
            Some("Give at least one address range its token is accepted from.")
        }
        Err(_) => Some("Write each address range like 192.0.2.0/24."),
        Ok(_) => None,
    };
    if let Some(problem) = problem {
        let refusal = ChangeError::Refused(format!("Not registered. {problem}"));
        return after(&portal, &signed_in, Err(refusal)).await;
    }
    let sources = sources.unwrap_or_default();
    match fleet::register(&portal.pool, &actor, name, &sources).await {
        Ok(registered) => {
            let shown = Some((name.to_owned(), registered.token));
            page(&portal, &signed_in, StatusCode::OK, None, shown).await
        }
        Err(fleet::RegisterError::Denied) => refused("Only a global admin can do this."),
        Err(fleet::RegisterError::Store(err)) => unavailable(err),
    }
}

/// "Save and apply" for the selected firewalls: every `firewall` field, in page order,
/// and the settings as TOML.
pub(crate) async fn push_settings(
    State(portal): State<Shared>,
    headers: HeaderMap,
    Form(fields): Form<Vec<(String, String)>>,
) -> Response {
    let field = |name: &str| {
        fields
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
            .unwrap_or_default()
    };
    let signed_in = match portal.signed_in_post(&headers, field("csrf")).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    let actor = match operator(&portal, &signed_in).await {
        Ok(actor) => actor,
        Err(answer) => return answer,
    };
    let firewalls: Option<Vec<i32>> = fields
        .iter()
        .filter(|(key, _)| key == "firewall")
        .map(|(_, id)| id.parse().ok())
        .collect();
    let Some(firewalls) = firewalls else {
        return not_found();
    };
    let done = fleet::push_settings(&portal.pool, &actor, &firewalls, field("toml"))
        .await
        .map(drop);
    after(&portal, &signed_in, done).await
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct ConfirmForm {
    csrf: String,
    confirm: String,
}

/// "Retire firewall", with its name typed (C72).
pub(crate) async fn retire(
    State(portal): State<Shared>,
    Path(id): Path<i32>,
    headers: HeaderMap,
    Form(form): Form<ConfirmForm>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    let actor = match operator(&portal, &signed_in).await {
        Ok(actor) => actor,
        Err(answer) => return answer,
    };
    let done = fleet::retire(&portal.pool, &actor, id, &form.confirm).await;
    after(&portal, &signed_in, done).await
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct CsrfForm {
    csrf: String,
}

/// "Resume" on a halted rollout (C71).
pub(crate) async fn resume(
    State(portal): State<Shared>,
    Path(id): Path<i32>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    let actor = match operator(&portal, &signed_in).await {
        Ok(actor) => actor,
        Err(answer) => return answer,
    };
    let done = fleet::resume(&portal.pool, &actor, id).await;
    after(&portal, &signed_in, done).await
}

/// "Skip" on a halted rollout (C71).
pub(crate) async fn skip(
    State(portal): State<Shared>,
    Path(id): Path<i32>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    let actor = match operator(&portal, &signed_in).await {
        Ok(actor) => actor,
        Err(answer) => return answer,
    };
    let done = fleet::skip(&portal.pool, &actor, id).await;
    after(&portal, &signed_in, done).await
}
