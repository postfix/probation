//! The policy editor, the same at every layer (mockup policy.html). A save runs
//! `authorized_place` (404) -> `check_edit` against `parent_policy` (the form again,
//! naming the blocking switch, C8) -> `authorize` (403) -> `save_edit` (the form again
//! on a revision conflict) (03 § Program behavior step 4).

use askama::Template;
use axum::extract::{Form, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use probation_policy::{
    Block, DigestAlgorithm, Ecosystem, EditRefusal, EditTarget, EffectivePolicy, Exception, Layer,
    LayerKind, Lifts, Loosening, OsvSetting, PlaceRef, SwitchName, check_edit,
};
use serde::Deserialize;

use super::{Shared, SignedIn, Top, not_found, redirect, refused, render, unavailable};
use crate::policy::{PolicyStore, SaveError, StoreError};
use crate::tenancy::{self, Authorized, Place, Role, authorize};

/// The longest freeze a layer may set (C44).
const MAX_FREEZE_SECONDS: u64 = 365 * DAY;
const DAY: u64 = 86_400;
const HOUR: u64 = 3_600;

/// What the page shows next to a kept looser value (C47, C124).
pub(crate) const NOT_IN_EFFECT: &str = "not in effect while a stricter rule above applies";

#[derive(Template)]
#[template(path = "policy.html")]
pub(crate) struct PolicyPage {
    pub top: Option<Top>,
    pub title: &'static str,
    pub csrf: String,
    pub view: PolicyView,
}

pub(crate) struct PolicyView {
    /// The layer's id in its path, e.g. `group-4`.
    pub id: String,
    pub label: String,
    /// The layers the session may open: (path, label, is this one).
    pub layers: Vec<(String, String, bool)>,
    pub chain: String,
    pub editable: bool,
    pub revision: u64,
    pub error: Option<String>,
    pub freeze: String,
    pub unit: &'static str,
    pub freeze_above: String,
    pub freeze_not_in_effect: bool,
    pub osv: &'static str,
    pub osv_above: String,
    pub osv_not_in_effect: bool,
    pub osv_choices: Vec<(&'static str, &'static str)>,
    pub blocks: Vec<BlockRow>,
    pub exceptions: Vec<ExceptionRow>,
    /// Only where a layer below exists (platform, organisation, group).
    pub switches: Vec<SwitchRow>,
    pub not_in_effect: &'static str,
}

pub(crate) struct BlockRow {
    pub ecosystem: String,
    pub package: String,
    pub what: String,
    pub set_by: String,
    /// Its position in this layer's own list; `None` when a layer above set it.
    pub own: Option<usize>,
}

pub(crate) struct ExceptionRow {
    pub ecosystem: String,
    pub package: String,
    pub covers: String,
    pub lifts: String,
    pub set_by: String,
    pub own: Option<usize>,
    pub not_in_effect: bool,
}

pub(crate) struct SwitchRow {
    pub name: &'static str,
    pub label: &'static str,
    pub checked: bool,
    /// The layer above does not give it, so it cannot be passed down (C45).
    pub disabled: bool,
    pub not_in_effect: bool,
}

/// `/policy`: the layer the session works on most: its organisation's for an org
/// admin, its group's for a group admin, else its own.
pub(crate) async fn start(State(portal): State<Shared>, headers: HeaderMap) -> Response {
    let signed_in = match portal.signed_in(&headers).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    let session = signed_in.tenancy_session();
    let account = match signed_in.account(&portal).await {
        Ok(Some(account)) => account,
        Ok(None) => return redirect("/keys"),
        Err(err) => return unavailable(err),
    };
    let tenancy = portal.tenancy();
    let role = match tenancy.actor(&session, &account).await {
        Ok(actor) => actor.role(account.place()),
        Err(err) => return unavailable(err),
    };
    if matches!(role, Some(Role::OrgAdmin | Role::GlobalAdmin)) {
        return redirect(&path_of(account.place()));
    }
    match tenancy.own_place(&session, &account).await {
        Ok(own) => {
            let group = own.group().map(|id| PlaceRef {
                kind: LayerKind::Group,
                id: id as u32,
            });
            if let Some(group) = group
                && let Ok(group) = tenancy.authorized_place(&session, group).await
                && let Ok(actor) = tenancy.actor(&session, &group).await
                && actor.role(group.place()) == Some(Role::GroupAdmin)
            {
                return redirect(&path_of(group.place()));
            }
            redirect(&path_of(own.place()))
        }
        Err(_) => redirect(&path_of(account.place())),
    }
}

pub(crate) fn path_of(place: PlaceRef) -> String {
    format!("/policy/{}-{}", tenancy::kind_str(place.kind), place.id)
}

/// `org-3` and the like.
fn parse_layer(id: &str) -> Option<PlaceRef> {
    let (kind, id) = id.split_once('-')?;
    Some(PlaceRef {
        kind: tenancy::kind_of(kind)?,
        id: id.parse().ok()?,
    })
}

pub(crate) async fn show(
    State(portal): State<Shared>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let signed_in = match portal.signed_in(&headers).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    let Some(place) = authorized(&portal, &signed_in, &id).await else {
        return not_found();
    };
    page(&portal, &signed_in, &place, StatusCode::OK, None).await
}

async fn authorized(
    portal: &super::Portal,
    signed_in: &SignedIn,
    id: &str,
) -> Option<Authorized<Place>> {
    let place = parse_layer(id)?;
    portal
        .tenancy()
        .authorized_place(&signed_in.tenancy_session(), place)
        .await
        .ok()
}

async fn page(
    portal: &super::Portal,
    signed_in: &SignedIn,
    place: &Authorized<Place>,
    status: StatusCode,
    error: Option<String>,
) -> Response {
    let built = async {
        let mut top = signed_in.top(portal).await?;
        top.page = "policy";
        let view = view(portal, signed_in, place, error).await?;
        Ok::<_, StoreError>(PolicyPage {
            csrf: top.csrf.clone(),
            top: Some(top),
            title: "Policy",
            view,
        })
    };
    match built.await {
        Ok(page) => render(status, &page),
        Err(StoreError::Db(err)) => unavailable(err),
        Err(StoreError::MissingLayer(_)) => not_found(),
    }
}

async fn view(
    portal: &super::Portal,
    signed_in: &SignedIn,
    place: &Authorized<Place>,
    error: Option<String>,
) -> Result<PolicyView, StoreError> {
    let store = PolicyStore::new(portal.pool.clone());
    let (parent, current) = store.parent_policy(place).await?;
    let (_, revision) = store.layer(place).await?;
    let session = signed_in.tenancy_session();
    let actor = portal.tenancy().actor(&session, place).await?;
    let editable = actor
        .role(place.place())
        .is_some_and(|role| role.may_edit(place.place().kind));
    let above = parent.rules_for(Ecosystem::Npm, "", "");
    let freeze_not_in_effect = current
        .freeze_seconds
        .is_some_and(|own| own < above.freeze_seconds && !parent.allow.shorter_freeze);
    let osv_not_in_effect = current
        .osv
        .is_some_and(|own| above.osv_from.is_some() && own < above.osv && !parent.allow.osv_off);
    let (freeze, unit) = match current.freeze_seconds {
        None => (String::new(), "days"),
        Some(seconds) if seconds % DAY == 0 => ((seconds / DAY).to_string(), "days"),
        Some(seconds) => ((seconds / HOUR).to_string(), "hours"),
    };
    let mut blocks: Vec<BlockRow> = parent
        .blocks
        .iter()
        .map(|owned| block_row(&owned.block, kind_label(owned.owner), None))
        .collect();
    blocks.extend(
        current
            .blocks
            .iter()
            .enumerate()
            .map(|(index, block)| block_row(block, "This layer".to_owned(), Some(index))),
    );
    let mut exceptions: Vec<ExceptionRow> = parent
        .exceptions
        .iter()
        .map(|owned| exception_row(&owned.exception, kind_label(owned.owner), None, false))
        .collect();
    exceptions.extend(
        current
            .exceptions
            .iter()
            .enumerate()
            .map(|(index, exception)| {
                let lifts = exception.lifts;
                let kept = (lifts.block && !parent.allow.exceptions)
                    || (lifts.freeze && !parent.allow.shorter_freeze)
                    || (lifts.osv && !parent.allow.osv_off);
                exception_row(exception, "This layer".to_owned(), Some(index), kept)
            }),
    );
    let switches = if matches!(
        place.place().kind,
        LayerKind::Platform | LayerKind::Org | LayerKind::Group
    ) {
        [
            (SwitchName::Exceptions, "allow_exceptions"),
            (SwitchName::OsvOff, "allow_osv_off"),
            (SwitchName::ShorterFreeze, "allow_shorter_freeze"),
        ]
        .into_iter()
        .map(|(switch, name)| SwitchRow {
            name,
            label: switch_label(switch),
            checked: current.allow.get(switch),
            disabled: !parent.allow.get(switch),
            not_in_effect: current.allow.get(switch) && !parent.allow.get(switch),
        })
        .collect()
    } else {
        Vec::new()
    };
    Ok(PolicyView {
        id: id_of(place.place()),
        label: place_label(place, signed_in.login_id),
        layers: layers(portal, signed_in, place).await?,
        chain: place
            .chain()
            .iter()
            .map(|link| kind_label(link.kind))
            .collect::<Vec<_>>()
            .join(" → "),
        editable,
        revision,
        error,
        freeze,
        unit,
        freeze_above: match above.freeze_from {
            Some(from) => format!(
                "From {}: {}.",
                kind_label(from),
                duration(above.freeze_seconds)
            ),
            None => "Nothing above sets a freeze.".to_owned(),
        },
        freeze_not_in_effect,
        osv: osv_name(current.osv),
        osv_above: match above.osv_from {
            Some(from) => format!("From {}: {}.", kind_label(from), osv_label(above.osv)),
            None => "Nothing above sets the OSV check.".to_owned(),
        },
        osv_not_in_effect,
        osv_choices: vec![
            ("inherit", "Inherit from the layer above"),
            ("on", "On: block them"),
            (
                "log_only",
                "Log only: let them through and record them in Activity as \"would have blocked\"",
            ),
            ("off", "Off: do not check"),
        ],
        blocks,
        exceptions,
        switches,
        not_in_effect: NOT_IN_EFFECT,
    })
}

/// The layers the session may open from its place: its organisation, its group (every
/// group for an org admin) and its own layer, or its personal account.
async fn layers(
    portal: &super::Portal,
    signed_in: &SignedIn,
    shown: &Authorized<Place>,
) -> Result<Vec<(String, String, bool)>, StoreError> {
    let session = signed_in.tenancy_session();
    let tenancy = portal.tenancy();
    let mut places: Vec<Authorized<Place>> = Vec::new();
    if let Some(account) = signed_in.account(portal).await? {
        let org_admin = matches!(
            tenancy
                .actor(&session, &account)
                .await?
                .role(account.place()),
            Some(Role::OrgAdmin | Role::GlobalAdmin)
        );
        if account.org().is_some() {
            places.push(account.clone());
            if org_admin {
                for group in tenancy::groups(&portal.pool, &account).await? {
                    let group = PlaceRef {
                        kind: LayerKind::Group,
                        id: group.id as u32,
                    };
                    if let Ok(group) = tenancy.authorized_place(&session, group).await {
                        places.push(group);
                    }
                }
            }
        }
        if let Ok(own) = tenancy.own_place(&session, &account).await {
            if !org_admin
                && let Some(group) = own.group()
                && let Ok(group) = tenancy
                    .authorized_place(
                        &session,
                        PlaceRef {
                            kind: LayerKind::Group,
                            id: group as u32,
                        },
                    )
                    .await
            {
                places.push(group);
            }
            places.push(own);
        }
    }
    if !places.iter().any(|place| place.place() == shown.place()) {
        places.push(shown.clone());
    }
    Ok(places
        .iter()
        .map(|place| {
            (
                path_of(place.place()),
                place_label(place, signed_in.login_id),
                place.place() == shown.place(),
            )
        })
        .collect())
}

fn id_of(place: PlaceRef) -> String {
    format!("{}-{}", tenancy::kind_str(place.kind), place.id)
}

/// "Frontend group (Acme)" and the like.
fn place_label(place: &Authorized<Place>, login: i32) -> String {
    let org = place.org_name().unwrap_or_default();
    match place.place().kind {
        LayerKind::Platform => "Platform".to_owned(),
        LayerKind::Org => format!("{org} organisation"),
        LayerKind::Group => format!("{} group ({org})", place.group_name().unwrap_or_default()),
        LayerKind::User if place.owner_login() == Some(login) => {
            format!("Your own policy in {org}")
        }
        LayerKind::User => format!("A member's own policy in {org}"),
        LayerKind::Personal => "Your personal account".to_owned(),
    }
}

fn kind_label(kind: LayerKind) -> String {
    match kind {
        LayerKind::Platform => "the platform",
        LayerKind::Org => "the organisation",
        LayerKind::Group => "the group",
        LayerKind::User => "the user",
        LayerKind::Personal => "the personal account",
    }
    .to_owned()
}

fn switch_label(switch: SwitchName) -> &'static str {
    match switch {
        SwitchName::Exceptions => "Allow package exceptions",
        SwitchName::OsvOff => "Allow turning OSV off",
        SwitchName::ShorterFreeze => "Allow a shorter freeze",
    }
}

fn duration(seconds: u64) -> String {
    match seconds {
        0 => "no freeze".to_owned(),
        s if s % DAY == 0 => format!("{} days", s / DAY),
        s => format!("{} hours", s / HOUR),
    }
}

fn osv_name(osv: Option<OsvSetting>) -> &'static str {
    match osv {
        None => "inherit",
        Some(OsvSetting::On) => "on",
        Some(OsvSetting::LogOnly) => "log_only",
        Some(OsvSetting::Off) => "off",
    }
}

fn osv_label(osv: OsvSetting) -> &'static str {
    match osv {
        OsvSetting::On => "on, block",
        OsvSetting::LogOnly => "log only",
        OsvSetting::Off => "off",
    }
}

fn ecosystem_label(ecosystem: Ecosystem) -> String {
    match ecosystem {
        Ecosystem::Npm => "npm",
        Ecosystem::PyPi => "PyPI",
    }
    .to_owned()
}

fn block_row(block: &Block, set_by: String, own: Option<usize>) -> BlockRow {
    let (ecosystem, package, what) = match block {
        Block::Package { ecosystem, name } => (
            ecosystem_label(*ecosystem),
            name.clone(),
            "Whole package".to_owned(),
        ),
        Block::Version {
            ecosystem,
            name,
            version,
        } => (
            ecosystem_label(*ecosystem),
            name.clone(),
            format!("Version {version}"),
        ),
        Block::File { algorithm, digest } => (
            "any".to_owned(),
            String::new(),
            format!(
                "Exact file with {} {digest}",
                match algorithm {
                    DigestAlgorithm::Sha256 => "sha256",
                    DigestAlgorithm::Sha512 => "sha512",
                }
            ),
        ),
    };
    BlockRow {
        ecosystem,
        package,
        what,
        set_by,
        own,
    }
}

fn exception_row(
    exception: &Exception,
    set_by: String,
    own: Option<usize>,
    not_in_effect: bool,
) -> ExceptionRow {
    let lifts = [
        (exception.lifts.block, "Blocklist"),
        (exception.lifts.freeze, "Freeze"),
        (exception.lifts.osv, "OSV"),
    ]
    .into_iter()
    .filter(|(on, _)| *on)
    .map(|(_, name)| name)
    .collect::<Vec<_>>()
    .join(", ");
    ExceptionRow {
        ecosystem: ecosystem_label(exception.ecosystem),
        package: exception.name.clone(),
        covers: match &exception.version {
            Some(version) => format!("Version {version}"),
            None => "Whole package, every version including future ones".to_owned(),
        },
        lifts,
        set_by,
        own,
        not_in_effect,
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub(crate) struct PolicyForm {
    csrf: String,
    revision: u64,
    /// `save`, `add_block`, `remove_block`, `add_exception` or `remove_exception`.
    action: String,
    freeze: String,
    unit: String,
    osv: String,
    allow_exceptions: Option<String>,
    allow_osv_off: Option<String>,
    allow_shorter_freeze: Option<String>,
    ecosystem: String,
    name: String,
    /// For a block: `package`, `version` or `file`.
    what: String,
    version: String,
    algorithm: String,
    digest: String,
    lifts_block: Option<String>,
    lifts_freeze: Option<String>,
    lifts_osv: Option<String>,
    index: usize,
}

/// One edit of the layer (03 § Program behavior step 4).
pub(crate) async fn edit(
    State(portal): State<Shared>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<PolicyForm>,
) -> Response {
    let signed_in = match portal.signed_in_post(&headers, &form.csrf).await {
        Ok(signed_in) => signed_in,
        Err(answer) => return answer,
    };
    let Some(place) = authorized(&portal, &signed_in, &id).await else {
        return not_found();
    };
    let store = PolicyStore::new(portal.pool.clone());
    let (parent, current) = match store.parent_policy(&place).await {
        Ok(found) => found,
        Err(StoreError::Db(err)) => return unavailable(err),
        Err(StoreError::MissingLayer(_)) => return not_found(),
    };
    let refuse = |message: String| {
        page(
            &portal,
            &signed_in,
            &place,
            StatusCode::UNPROCESSABLE_ENTITY,
            Some(message),
        )
    };
    let proposed = match proposed(&current, &form) {
        Ok(proposed) => proposed,
        Err(problem) => return refuse(format!("Not saved. {problem}")).await,
    };
    let target = EditTarget {
        place: place.place(),
        expected_revision: form.revision,
    };
    let checked = match check_edit(&parent, &current, target, proposed) {
        Ok(checked) => checked,
        Err(refusal) => return refuse(refusal_text(&parent, &refusal)).await,
    };
    let session = signed_in.tenancy_session();
    let actor = match portal.tenancy().actor(&session, &place).await {
        Ok(actor) => actor,
        Err(err) => return unavailable(err),
    };
    let Ok(permit) = authorize(&actor, &checked) else {
        return refused("Your role cannot change this layer.");
    };
    match store.save_edit(&actor, permit, checked).await {
        Ok(_) => redirect(&path_of(place.place())),
        Err(SaveError::Conflict) => {
            page(
                &portal,
                &signed_in,
                &place,
                StatusCode::CONFLICT,
                Some("Not saved. This layer was changed meanwhile by someone else; here it is as it is now. Make your change again.".to_owned()),
            )
            .await
        }
        Err(SaveError::WrongPlace) => refused("Your role cannot change this layer."),
        Err(SaveError::Db(err)) => unavailable(err),
    }
}

/// The stored layer with the form's one change; `Err` names what is wrong with it.
fn proposed(current: &Layer, form: &PolicyForm) -> Result<Layer, String> {
    let mut layer = current.clone();
    match form.action.as_str() {
        "save" => {
            layer.freeze_seconds = freeze(&form.freeze, &form.unit)?;
            layer.osv = match form.osv.as_str() {
                "inherit" | "" => None,
                "on" => Some(OsvSetting::On),
                "log_only" => Some(OsvSetting::LogOnly),
                "off" => Some(OsvSetting::Off),
                _ => return Err("Choose an OSV setting.".to_owned()),
            };
            if matches!(
                layer.kind,
                LayerKind::Platform | LayerKind::Org | LayerKind::Group
            ) {
                layer.allow.exceptions = form.allow_exceptions.is_some();
                layer.allow.osv_off = form.allow_osv_off.is_some();
                layer.allow.shorter_freeze = form.allow_shorter_freeze.is_some();
            }
        }
        "add_block" => layer.blocks.push(new_block(form)?),
        "remove_block" if form.index < layer.blocks.len() => {
            layer.blocks.remove(form.index);
        }
        "add_exception" => {
            let ecosystem = ecosystem(&form.ecosystem)?;
            let lifts = Lifts {
                block: form.lifts_block.is_some(),
                freeze: form.lifts_freeze.is_some(),
                osv: form.lifts_osv.is_some(),
            };
            if lifts == Lifts::default() {
                return Err("Tick at least one check the exception lets it through.".to_owned());
            }
            let version = form.version.trim();
            layer.exceptions.push(Exception {
                ecosystem,
                name: form.name.trim().to_owned(),
                version: (!version.is_empty()).then(|| version.to_owned()),
                lifts,
            });
        }
        "remove_exception" if form.index < layer.exceptions.len() => {
            layer.exceptions.remove(form.index);
        }
        _ => return Err("That change is not one this page makes.".to_owned()),
    }
    Ok(layer)
}

/// A freeze from the form: empty inherits; otherwise 0 hours to 365 days (C44).
fn freeze(value: &str, unit: &str) -> Result<Option<u64>, String> {
    const RANGE: &str = "Choose a freeze from 0 hours to 365 days.";
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let count: u64 = value.parse().map_err(|_| RANGE.to_owned())?;
    let seconds = match unit {
        "hours" => count.checked_mul(HOUR),
        "days" => count.checked_mul(DAY),
        _ => None,
    };
    match seconds {
        Some(seconds) if seconds <= MAX_FREEZE_SECONDS => Ok(Some(seconds)),
        _ => Err(RANGE.to_owned()),
    }
}

/// Blocks and exceptions on a package always name their ecosystem (C31).
fn ecosystem(value: &str) -> Result<Ecosystem, String> {
    Ecosystem::from_tag(value).ok_or_else(|| "Choose npm or PyPI.".to_owned())
}

fn new_block(form: &PolicyForm) -> Result<Block, String> {
    let name = form.name.trim().to_owned();
    match form.what.as_str() {
        "package" => Ok(Block::Package {
            ecosystem: ecosystem(&form.ecosystem)?,
            name,
        }),
        "version" => Ok(Block::Version {
            ecosystem: ecosystem(&form.ecosystem)?,
            name,
            version: form.version.trim().to_owned(),
        }),
        // A file is named by its digest alone, as in today's blocklist (C119).
        "file" => Ok(Block::File {
            algorithm: match form.algorithm.as_str() {
                "sha512" => DigestAlgorithm::Sha512,
                _ => DigestAlgorithm::Sha256,
            },
            digest: form.digest.trim().to_ascii_lowercase(),
        }),
        _ => Err("Choose a whole package, one version or one exact file.".to_owned()),
    }
}

/// The refusal as the form shows it, naming the switch and the layer above that has it
/// off (C8, C45).
fn refusal_text(parent: &EffectivePolicy, refusal: &EditRefusal) -> String {
    let holder = |switch: SwitchName| {
        parent
            .chain
            .iter()
            .find(|layer| !layer.allow.get(switch))
            .map_or_else(
                || "the layer above".to_owned(),
                |layer| kind_label(layer.kind),
            )
    };
    match refusal {
        EditRefusal::NotAllowedByParent { what, switch } => {
            let change = match what {
                Loosening::ShorterFreeze { seconds } => {
                    format!("You set the freeze to {}", duration(*seconds))
                }
                Loosening::Osv(osv) => format!("You set the OSV check to {}", osv_label(*osv)),
                Loosening::Exception { name, .. } => {
                    format!("You asked for an exception on {name}")
                }
            };
            format!(
                "Not saved. {change}, but {} does not allow it below: its switch \"{}\" is off.",
                holder(*switch),
                switch_label(*switch)
            )
        }
        EditRefusal::GrantNotHeld { switch } => format!(
            "Not saved. You cannot pass down \"{}\": {} does not allow it here.",
            switch_label(*switch),
            holder(*switch)
        ),
        EditRefusal::Invalid(problem) => format!("Not saved: {problem}."),
    }
}
