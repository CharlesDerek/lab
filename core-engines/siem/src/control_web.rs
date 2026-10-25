use crate::{
    ecosystem::IncidentRequest,
    identity::{Actor, Role},
    model::now_ms,
    render::escape,
    web::{App, WebError},
};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Extension, Form, Json, Router,
};
use orchestrator::governor::{Request, Resources};
use serde::Deserialize;
use serde_json::{json, Value};
use std::fmt::Write;

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum ControlCommand {
    BackgroundPool {
        pool: String,
    },
    ConfigureSignals {
        policy: crate::signals::SignalPolicy,
    },
    CompactSignals,
    ReplaySignals,
    ReplaySignalPage {
        after: u64,
        limit: usize,
    },
    MapIdentity {
        source: String,
        principal: String,
        canonical: String,
        endpoint_uid: Option<(String, u32)>,
    },
    ConfigurePool {
        pool: String,
        capacity: Resources,
        essential_reserve: Resources,
    },
    BindEndpoint {
        endpoint: String,
        pool: String,
    },
    Reserve {
        request: Request,
    },
    Release {
        id: String,
        generation: u64,
    },
    ProposeIncident {
        request: IncidentRequest,
    },
    ApproveIncident {
        id: String,
        plan_hash: String,
    },
    RecoverIncident {
        id: String,
        plan_hash: String,
        note: String,
    },
    IssueOperator {
        id: String,
        role: Role,
        expires_ms: u64,
    },
    RevokeOperator {
        id: String,
    },
}
impl ControlCommand {
    pub(crate) fn permitted(&self, actor: &Actor) -> bool {
        match self {
            Self::BackgroundPool { .. }
            | Self::ConfigureSignals { .. }
            | Self::CompactSignals
            | Self::MapIdentity { .. }
            | Self::IssueOperator { .. }
            | Self::RevokeOperator { .. }
            | Self::ConfigurePool { .. }
            | Self::BindEndpoint { .. } => actor.role == Role::Admin,
            Self::ProposeIncident { .. } => actor.role != Role::Viewer,
            _ => matches!(actor.role, Role::Admin | Role::Responder),
        }
    }
    pub(crate) fn execute(
        self,
        e: &crate::engine::Engine,
        actor: &Actor,
    ) -> crate::engine::LabResult<Value> {
        let now = now_ms();
        Ok(match self {
            Self::BackgroundPool { pool } => {
                e.configure_background_pool(&pool, now)?;
                json!({"background_pool":pool})
            }
            Self::ConfigureSignals { policy } => {
                e.configure_signal_policy(&policy, now)?;
                json!({"policy":policy})
            }
            Self::CompactSignals => {
                let (before, after) = e.compact_signals(now)?;
                json!({"before_bytes":before,"after_bytes":after})
            }
            Self::ReplaySignals => json!({"evaluated":e.replay_signals(now)?}),
            Self::ReplaySignalPage { after, limit } => {
                let (evaluated, next) = e.replay_signal_page(after, limit, now)?;
                json!({"evaluated":evaluated,"next":next})
            }
            Self::MapIdentity {
                source,
                principal,
                canonical,
                endpoint_uid,
            } => {
                e.map_signal_identity(
                    &source,
                    &principal,
                    &canonical,
                    endpoint_uid.as_ref().map(|(id, uid)| (id.as_str(), *uid)),
                    now,
                )?;
                json!({"mapped":canonical})
            }
            Self::ConfigurePool {
                pool,
                capacity,
                essential_reserve,
            } => {
                e.configure_pool(&pool, capacity, essential_reserve, now)?;
                json!({"configured":pool})
            }
            Self::BindEndpoint { endpoint, pool } => {
                e.bind_endpoint_pool(&endpoint, &pool, now)?;
                json!({"bound":endpoint,"pool":pool})
            }
            Self::Reserve { request } => serde_json::to_value(e.reserve_resources(&request, now)?)?,
            Self::Release { id, generation } => {
                e.release_resources(&id, generation, now)?;
                json!({"released":id})
            }
            Self::ProposeIncident { request } => {
                serde_json::to_value(e.propose_incident(&request, now)?)?
            }
            Self::ApproveIncident { id, plan_hash } => {
                serde_json::to_value(e.approve_incident(&id, &plan_hash, &actor.id, now)?)?
            }
            Self::RecoverIncident {
                id,
                plan_hash,
                note,
            } => serde_json::to_value(e.recover_incident(&id, &plan_hash, &actor.id, &note, now)?)?,
            Self::IssueOperator {
                id,
                role,
                expires_ms,
            } => serde_json::to_value(e.issue_operator(&id, role, expires_ms, now)?)?,
            Self::RevokeOperator { id } => {
                e.revoke_operator(&id, now)?;
                json!({"revoked":id})
            }
        })
    }
}
pub fn routes() -> Router<App> {
    Router::new()
        .route("/control", get(portal))
        .route("/control/action", post(action))
        .route("/control/setup", post(crate::control_setup::submit))
        .route("/api/control", get(state).post(control))
        .route("/api/control/incidents/{id}", get(incident))
        .route("/api/control/audit", get(audit))
        .route("/api/control/signals/{id}", get(signal_fact))
        .route("/api/ingest/{source}/signals", post(ingest_signals))
        .route("/api/ingest/{source}/kubernetes", post(ingest_kubernetes))
}
fn checked<T>(result: crate::engine::LabResult<T>) -> Result<T, WebError> {
    result.map_err(|e| WebError(e.to_string()))
}
async fn state(State(app): State<App>) -> Result<Json<Value>, WebError> {
    let e = app
        .engine
        .lock()
        .map_err(|_| WebError("Engine unavailable".into()))?;
    Ok(Json(
        json!({"pools":checked(e.resource_pools())?,"incidents":checked(e.incidents())?,"operators":checked(e.operators())?,"audit_checkpoint":checked(e.audit_checkpoint())?,"signal_coverage":checked(e.signal_coverage())?,"background_measurements":checked(e.background_measurements())?}),
    ))
}
async fn signal_fact(State(app): State<App>, Path(id): Path<u64>) -> Result<Json<Value>, WebError> {
    let e = app
        .engine
        .lock()
        .map_err(|_| WebError("Engine unavailable".into()))?;
    Ok(Json(json!(checked(e.signal_fact(id))?)))
}
async fn ingest_signals(
    State(app): State<App>,
    Path(source): Path<String>,
    headers: HeaderMap,
    Json(signals): Json<Vec<crate::signals::Signal>>,
) -> Result<Json<Value>, WebError> {
    let mut e = app
        .engine
        .lock()
        .map_err(|_| WebError("Engine unavailable".into()))?;
    Ok(Json(
        json!({"accepted":checked(e.ingest_signals(&source,crate::fleet_web::bearer(&headers),&signals,now_ms()))?}),
    ))
}
async fn ingest_kubernetes(
    State(app): State<App>,
    Path(source): Path<String>,
    headers: HeaderMap,
    Json(batch): Json<crate::signals::KubernetesBatch>,
) -> Result<Json<Value>, WebError> {
    let signals = checked(batch.normalize())?;
    let mut e = app
        .engine
        .lock()
        .map_err(|_| WebError("Engine unavailable".into()))?;
    Ok(Json(
        json!({"accepted":checked(e.ingest_signals(&source,crate::fleet_web::bearer(&headers),&signals,now_ms()))?}),
    ))
}
async fn incident(State(app): State<App>, Path(id): Path<String>) -> Result<Json<Value>, WebError> {
    let e = app
        .engine
        .lock()
        .map_err(|_| WebError("Engine unavailable".into()))?;
    Ok(Json(json!(checked(e.incident(&id))?)))
}
#[derive(Default, Deserialize)]
struct AuditQuery {
    #[serde(default)]
    after: u64,
}
async fn audit(
    State(app): State<App>,
    Query(query): Query<AuditQuery>,
) -> Result<Json<Value>, WebError> {
    let e = app
        .engine
        .lock()
        .map_err(|_| WebError("Engine unavailable".into()))?;
    Ok(Json(
        json!({"records":checked(e.export_audit(query.after,256))?,"checkpoint":checked(e.audit_checkpoint())?}),
    ))
}
async fn control(
    State(app): State<App>,
    Extension(actor): Extension<Actor>,
    headers: HeaderMap,
    Json(command): Json<ControlCommand>,
) -> Response {
    if !command.permitted(&actor) {
        return StatusCode::FORBIDDEN.into_response();
    }
    if crate::fleet_web::bearer(&headers).is_empty()
        && !headers
            .get("x-athernex-csrf")
            .and_then(|h| h.to_str().ok())
            .is_some_and(|v| crate::gateway::same_secret(v, &app.csrf))
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Ok(e) = app.engine.lock() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    match command.execute(&e, &actor) {
        Ok(value) => Json(value).into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":error.to_string()})),
        )
            .into_response(),
    }
}
#[derive(Deserialize)]
struct ActionForm {
    csrf: String,
    operation: String,
    id: String,
    plan_hash: String,
    #[serde(default)]
    note: String,
}
async fn action(
    State(app): State<App>,
    Extension(actor): Extension<Actor>,
    Form(form): Form<ActionForm>,
) -> Response {
    if !crate::gateway::same_secret(&form.csrf, &app.csrf) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let command = match form.operation.as_str() {
        "approve" => ControlCommand::ApproveIncident {
            id: form.id,
            plan_hash: form.plan_hash,
        },
        "recover" => ControlCommand::RecoverIncident {
            id: form.id,
            plan_hash: form.plan_hash,
            note: form.note,
        },
        _ => return StatusCode::BAD_REQUEST.into_response(),
    };
    if !command.permitted(&actor) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Ok(e) = app.engine.lock() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    match command.execute(&e, &actor) {
        Ok(_) => Redirect::to("/control").into_response(),
        Err(error) => WebError(error.to_string()).into_response(),
    }
}
async fn portal(
    State(app): State<App>,
    Extension(actor): Extension<Actor>,
) -> Result<Html<String>, WebError> {
    let e = app
        .engine
        .lock()
        .map_err(|_| WebError("Engine unavailable".into()))?;
    let pools = checked(e.resource_pools())?;
    let incidents = checked(e.incidents())?;
    let mut content=String::from("<section class=page-heading><div><div class=eyebrow>SHARED CONTROL PLANE</div><h1>Security and capacity</h1><p>Review containment together with placement holds and replacement capacity. Recovery requires a successful response, fresh health and an operator verification note.</p><a class=button href=/engine-updates>Engine releases</a><a class=button href=/analysis>Investigation assistant</a></div></section><section class='panel controls-panel fleet-panel'><h2>Resource pools</h2>");
    if pools.is_empty() {
        content.push_str("<p>No resource pools configured. Register capacity and bind each managed endpoint before proposing an incident response.</p>");
    }
    for p in pools {
        write!(content,"<h3>{}</h3><p>CPU: {} / {} millicores · Memory: {} / {} MiB · GPU: {} / {} milliunits · Tokens: {} / {}</p><p>Placement: {}</p>",escape(&p.name),p.used.cpu_millis,p.capacity.cpu_millis,p.used.memory_mib,p.capacity.memory_mib,p.used.gpu_millis,p.capacity.gpu_millis,p.used.tokens,p.capacity.tokens,if p.holds.is_empty(){"Available".into()}else{format!("Held: {}",escape(&p.holds.join(", ")))}).unwrap();
    }
    content.push_str(
        "</section><section class='panel controls-panel fleet-panel'><h2>Incident responses</h2>",
    );
    if incidents.is_empty() {
        content.push_str("<p>No incident responses proposed.</p>");
    }
    for incident in incidents {
        let plan = &incident.plan;
        write!(content,"<article><h3>{}</h3><p>Review: {} · Endpoint response: {}</p><p>Hold {} and reserve {} CPU millicores / {} MiB on {}. Quarantine the exact file bound to <a href='/event/{}'>evidence {}</a>.</p><a class=button href='/case/{}'>Open investigation</a>",escape(&plan.request.id),escape(&incident.state),escape(&incident.response_state),escape(&plan.affected_pool),plan.request.resources.cpu_millis,plan.request.resources.memory_mib,escape(&plan.request.replacement_pool),plan.request.evidence_id,plan.request.evidence_id,plan.case_id).unwrap();
        if matches!(actor.role, Role::Admin | Role::Responder) {
            let operation = if incident.state == "pending" {
                Some(("approve", "Approve containment and reserve capacity"))
            } else if incident.state == "approved" && incident.response_state == "succeeded" {
                Some(("recover", "Confirm recovery and restore placement"))
            } else {
                None
            };
            if let Some((op, label)) = operation {
                write!(content,"<form method=post action=/control/action><input type=hidden name=csrf value='{}'><input type=hidden name=operation value='{op}'><input type=hidden name=id value='{}'><input type=hidden name=plan_hash value='{}'>",escape(&app.csrf),escape(&plan.request.id),escape(&incident.plan_hash)).unwrap();
                if op == "recover" {
                    content.push_str("<label>Recovery verification<textarea name=note required maxlength=1000></textarea></label>");
                }
                write!(content, "<button class=button>{label}</button></form>").unwrap();
            }
        }
        content.push_str("</article>");
    }
    content.push_str("</section>");
    content.push_str(&checked(crate::control_setup::render(
        &e, &actor, &app.csrf,
    ))?);
    let checkpoint = checked(e.audit_checkpoint())?;
    write!(content,"<section class='panel controls-panel fleet-panel'><h2>Audit continuity</h2><p>{} durable records. Export checkpoints to an independently controlled location to detect later history changes.</p><a class=button href=/api/control/audit>Export audit records and checkpoint</a></section>",checkpoint.sequence).unwrap();
    Ok(Html(
        crate::render::page(
            &checked(e.snapshot())?,
            "control",
            &Default::default(),
            None,
            &app.csrf,
        )
        .replace("<!-- CONTROL_CONTENT -->", &content),
    ))
}
