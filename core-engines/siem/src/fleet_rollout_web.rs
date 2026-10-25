use crate::{
    engine::LabResult,
    fleet_rollout::{RolloutRecord, RolloutRequest},
    fleet_update_web,
    model::now_ms,
    render::escape,
    web::{App, WebError},
};
use athernex_endpoint_protocol::update::Component;
use axum::{
    extract::{Path, State},
    response::{Html, Redirect},
    routing::{get, post},
    Extension, Form, Json, Router,
};
use std::{collections::HashMap, fmt::Write as _, path::PathBuf, sync::Arc};

fn checked<T>(result: LabResult<T>) -> Result<T, WebError> {
    result.map_err(|e| WebError(e.to_string()))
}
pub fn routes() -> Router<App> {
    Router::new()
        .route("/endpoint-rollouts", get(portal))
        .route("/endpoints/rollouts/action", post(action))
        .route("/api/endpoint-rollouts", get(records))
        .route("/api/endpoint-rollouts/{id}", get(record))
}
async fn records(State(app): State<App>) -> Result<Json<Vec<RolloutRecord>>, WebError> {
    let engine = app
        .engine
        .lock()
        .map_err(|_| WebError("Engine unavailable".into()))?;
    Ok(Json(checked(engine.endpoint_rollouts())?))
}
async fn record(
    State(app): State<App>,
    Path(id): Path<String>,
) -> Result<Json<RolloutRecord>, WebError> {
    let engine = app
        .engine
        .lock()
        .map_err(|_| WebError("Engine unavailable".into()))?;
    Ok(Json(checked(engine.endpoint_rollout(&id))?))
}
fn form(csrf: &str, op: &str, id: &str, hash: &str) -> String {
    format!("<form class=control-form method=post action=/endpoints/rollouts/action><input type=hidden name=csrf value='{}'><input type=hidden name=op value='{}'><input type=hidden name=id value='{}'><input type=hidden name=plan_hash value='{}'>",escape(csrf),escape(op),escape(id),escape(hash))
}
async fn portal(
    State(app): State<App>,
    Extension(root): Extension<Arc<PathBuf>>,
) -> Result<Html<String>, WebError> {
    let releases = if root.join("public-key.txt").exists() {
        let key = checked(fleet_update_web::public_key(&root))?;
        checked(fleet_update_web::catalog(&root, &key))?
    } else {
        Vec::new()
    };
    let engine = app
        .engine
        .lock()
        .map_err(|_| WebError("Engine unavailable".into()))?;
    let fleet = checked(engine.fleet())?;
    let records = checked(engine.endpoint_rollouts())?;
    let snapshot = checked(engine.snapshot())?;
    let now = now_ms();
    let mut html=String::from("<section class=page-heading><div><div class=eyebrow>ENDPOINT RELEASES</div><h1>Fleet rollouts</h1><p>Install an exact signed release in reviewed groups. Every device in a group must finish installation and provide fresh healthy reports spanning the observation window before the next group begins. A failed member stops further dispatch.</p><a class=button href=/endpoint-updates>Signed endpoint updates</a></div></section>");
    html.push_str("<section class='panel controls-panel fleet-panel'><h2>Plan a rollout</h2><p>Select up to 64 devices that permit automatic installation. The first group contains your canaries; later groups use the batch size below. Existing protection scope, collection and signature health must be preserved. All devices must match the release platform, key and channel.</p>");
    if releases.is_empty() {
        html.push_str("<p>Publish a signed release before planning a rollout.</p>");
    } else {
        html.push_str(&form(&app.csrf, "propose", "", ""));
        html.push_str("<label>Component<select name=component><option value=agent>Agent</option><option value=controller>Controller</option></select></label><label>Name<input name=name required maxlength=64 placeholder='Workstation rollout'></label><label>Signed release<select name=release_id required>");
        for release in releases.iter().filter(|r| r.release.expires_ms > now) {
            write!(
                html,
                "<option value='{}'>{} · {} · sequence {}</option>",
                release.id().map_err(WebError)?,
                escape(&release.release.target),
                escape(&release.release.version),
                release.release.sequence
            )
            .unwrap();
        }
        html.push_str("</select></label><label>Later group size<input type=number name=batch_size min=1 max=16 value=4 required></label><label>Healthy observation per group (seconds)<input type=number name=observe_secs min=60 max=3600 value=300 required></label><label>Start in (minutes)<input type=number name=start_delay_minutes min=0 max=10079 value=0 required></label><label>Finish within (minutes from proposal)<input type=number name=deadline_minutes min=3 max=10080 value=1440 required></label><details open><summary>Choose devices and groups</summary>");
        for endpoint in fleet.endpoints.iter().filter(|e| {
            e.state == "active"
                && [
                    e.health.updates.as_ref(),
                    e.health.controller_updates.as_ref(),
                ]
                .into_iter()
                .flatten()
                .any(|u| u.automatic && u.managed && u.supervised)
        }) {
            let platform = match endpoint.platform {
                athernex_endpoint_protocol::Platform::Linux => "Linux",
                athernex_endpoint_protocol::Platform::Windows => "Windows",
                athernex_endpoint_protocol::Platform::Macos => "macOS",
            };
            let permitted = |component| {
                let health = match component {
                    Component::Agent => &endpoint.health.updates,
                    Component::Controller => &endpoint.health.controller_updates,
                };
                if health
                    .as_ref()
                    .is_some_and(|u| u.automatic && u.managed && u.supervised)
                {
                    "enabled"
                } else {
                    "disabled"
                }
            };
            write!(html,"<label>{}<small>Agent: {} · controller: {} · {platform} {} · {} · device {}</small><select name='target_{}'><option value=skip>Skip</option><option value=canary>First group (canary)</option><option value=later>Later groups</option></select></label>",escape(&endpoint.hostname),permitted(Component::Agent),permitted(Component::Controller),escape(&endpoint.arch),crate::render::age(endpoint.last_seen_ms),escape(endpoint.id.get(56..).unwrap_or(&endpoint.id)),endpoint.id).unwrap();
        }
        html.push_str("</details><button class=button>Propose fleet rollout</button></form>");
    }
    html.push_str("</section>");
    for record in &records {
        let plan = &record.plan;
        let request = &plan.request;
        write!(html,"<section class='panel controls-panel fleet-panel'><p>Component: {}</p><h2>{} · {}</h2><p>{}</p><p>{} · version {} · sequence {} · {} devices</p><p>First group: {} · later groups: up to {} · healthy observation: {} seconds</p><p>Start: {} · deadline: {}</p>",plan.component.label(),escape(&request.name),escape(&record.state),escape(&record.reason),escape(&plan.release.release.target),escape(&plan.release.release.version),plan.release.release.sequence,record.members.len(),request.canary_count,request.batch_size,request.observe_secs,if request.not_before_ms<=now{"window open".into()}else{format!("in {} minutes",(request.not_before_ms-now).div_ceil(60_000))},if request.deadline_ms<=now{"expired".into()}else{format!("in {} minutes",(request.deadline_ms-now).div_ceil(60_000))}).unwrap();
        html.push_str("<p>Approval includes automatic installation and service restarts on these exact devices. Pause/cancel stops new delivery and installation starts. Started installations finish or recover; already installed devices stay on their confirmed release.</p><details open><summary>Devices and observed health</summary>");
        for (index, member) in record.members.iter().enumerate() {
            let name = fleet
                .endpoints
                .iter()
                .find(|e| e.id == member.endpoint_id)
                .map(|e| e.hostname.as_str())
                .unwrap_or(&member.endpoint_id);
            let observed = member
                .healthy_since_ms
                .zip(member.last_healthy_ms)
                .map(|(first, last)| last.saturating_sub(first) / 1000)
                .unwrap_or(0);
            write!(html,"<article><h3>{} · group {}</h3><p>{} · observed healthy {} / {} seconds</p><p>Required: {}{}{}{} and update health</p><a href='/endpoints/{}'>Device evidence</a><details><summary>Device identity</summary><code>{}</code></details></article>",escape(name),member.cohort+1,escape(member.deployment_state.as_deref().unwrap_or("waiting for group")),observed,request.observe_secs,if plan.gates[index].protection_fingerprint.is_some(){"native protection, "}else{""},if plan.gates[index].collector{"collection, "}else{""},if plan.gates[index].signatures{"signatures, "}else{""},plan.component.label(),member.endpoint_id,member.endpoint_id).unwrap();
        }
        html.push_str("</details>");
        let actions: &[(&str, &str)] = match record.state.as_str() {
            "pending" => &[
                ("approve", "Approve exact rollout and installation"),
                ("cancel", "Cancel rollout"),
            ],
            "scheduled" | "running" => &[("pause", "Pause rollout"), ("cancel", "Cancel rollout")],
            "paused" => &[
                ("resume", "Resume reviewed rollout"),
                ("cancel", "Cancel rollout"),
            ],
            _ => &[],
        };
        for (op, label) in actions {
            html.push_str(&form(&app.csrf, op, &record.id, &record.plan_hash));
            write!(html, "<button class=button>{label}</button></form>").unwrap();
        }
        write!(html,"<details><summary>Exact approval content</summary><p>Plan SHA-256</p><code>{}</code><pre class=raw-message>{}</pre></details><a class=button href='/api/endpoint-rollouts/{}'>Export rollout record</a></section>",record.plan_hash,escape(&serde_json::to_string_pretty(plan).map_err(|e|WebError(e.to_string()))?),record.id).unwrap();
    }
    Ok(Html(
        crate::render::page(
            &snapshot,
            "endpoints",
            &crate::web::Filters::default(),
            None,
            &app.csrf,
        )
        .replace("<!-- ENDPOINT_CONTENT -->", &html),
    ))
}
async fn action(
    State(app): State<App>,
    Extension(root): Extension<Arc<PathBuf>>,
    Form(fields): Form<HashMap<String, String>>,
) -> Result<Redirect, WebError> {
    let field = |name: &str| {
        fields
            .get(name)
            .map(String::as_str)
            .ok_or_else(|| WebError(format!("Missing {name}")))
    };
    if !crate::gateway::same_secret(field("csrf")?, &app.csrf) {
        return Err(WebError("Session token rejected".into()));
    }
    let op = field("op")?;
    let now = now_ms();
    let proposed = if op == "propose" {
        let number = |name: &str| {
            field(name)?
                .parse::<u64>()
                .map_err(|_| WebError(format!("Invalid {name}")))
        };
        let mut canaries = Vec::new();
        let mut later = Vec::new();
        for (key, value) in &fields {
            if let Some(id) = key.strip_prefix("target_") {
                match value.as_str() {
                    "canary" => canaries.push(id.into()),
                    "later" => later.push(id.into()),
                    "skip" => {}
                    _ => return Err(WebError("Invalid device group".into())),
                }
            }
        }
        canaries.sort();
        later.sort();
        let canary_count = canaries.len();
        canaries.extend(later);
        let offset = |name: &str| {
            number(name)?
                .checked_mul(60_000)
                .and_then(|n| now.checked_add(n))
                .ok_or_else(|| WebError("Invalid rollout window".into()))
        };
        let request = RolloutRequest {
            name: field("name")?.into(),
            endpoint_ids: canaries,
            canary_count,
            batch_size: usize::try_from(number("batch_size")?)
                .map_err(|_| WebError("Invalid group size".into()))?,
            observe_secs: number("observe_secs")?,
            not_before_ms: offset("start_delay_minutes")?,
            deadline_ms: offset("deadline_minutes")?,
        };
        let component = match fields
            .get("component")
            .map(String::as_str)
            .unwrap_or("agent")
        {
            "agent" => Component::Agent,
            "controller" => Component::Controller,
            _ => return Err(WebError("Invalid rollout component".into())),
        };
        let key = checked(fleet_update_web::public_key(&root))?;
        Some((
            component,
            request,
            checked(fleet_update_web::release(&root, field("release_id")?, &key))?,
            key,
        ))
    } else {
        None
    };
    let engine = app
        .engine
        .lock()
        .map_err(|_| WebError("Engine unavailable".into()))?;
    if let Some((component, request, release, key)) = proposed {
        checked(engine.propose_component_rollout(request, &release, &key, component, now))?;
    } else {
        checked(engine.review_endpoint_rollout(field("id")?, field("plan_hash")?, op, now))?;
    }
    Ok(Redirect::to("/endpoint-rollouts"))
}
