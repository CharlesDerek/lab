use crate::{
    identity::{Actor, Role},
    investigator::{Investigation, InvestigationRequest},
    web::{App, WebError},
};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Extension, Form, Json, Router,
};
use serde::Deserialize;
use std::sync::{Arc, OnceLock};
static WORKERS: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Run {
    request: InvestigationRequest,
    backend: String,
}
pub fn routes() -> Router<App> {
    Router::new()
        .route("/analysis", get(portal))
        .route("/analysis/run", post(run_form))
        .route("/analysis/{id}", get(result_page))
        .route("/api/investigations", post(run))
        .route("/api/investigations/{id}", get(job))
        .route("/api/investigations/{id}/cancel", post(cancel))
}

fn page(app: &App, e: &crate::engine::Engine, content: &str) -> Result<Html<String>, WebError> {
    Ok(Html(
        crate::render::page(
            &e.snapshot().map_err(|e| WebError(e.to_string()))?,
            "analysis",
            &Default::default(),
            None,
            &app.csrf,
        )
        .replace("<!-- ANALYSIS_CONTENT -->", content),
    ))
}
async fn portal(
    State(app): State<App>,
    Extension(actor): Extension<Actor>,
) -> Result<Html<String>, WebError> {
    use crate::render::escape;
    use std::fmt::Write;
    let e = app
        .engine
        .lock()
        .map_err(|_| WebError("Engine unavailable".into()))?;
    let mut html=String::from("<section class=page-heading><div><div class=eyebrow>EVIDENCE-BOUND INVESTIGATION</div><h1>Investigation assistant</h1><p>Compare observed facts with a structured model analysis. Assertions must cite exact retained evidence; hypotheses remain separate. Results never authorize endpoint actions.</p></div></section>");
    if actor.role != Role::Viewer {
        write!(html,"<section class='panel controls-panel fleet-panel'><form method=post action=/analysis/run><input type=hidden name=csrf value='{}'><label>Investigation<select name=case_id>",escape(&app.csrf)).unwrap();
        for case in e
            .cases()
            .map_err(|e| WebError(e.to_string()))?
            .into_iter()
            .filter(|c| crate::operations::case_open(&c.status))
        {
            write!(
                html,
                "<option value='{}'>{}</option>",
                case.id,
                escape(&case.title)
            )
            .unwrap();
        }
        html.push_str("</select></label><label>Resource pool<select name=pool>");
        for pool in e.resource_pools().map_err(|e| WebError(e.to_string()))? {
            write!(
                html,
                "<option value='{}'>{}</option>",
                escape(&pool.name),
                escape(&pool.name)
            )
            .unwrap();
        }
        html.push_str("</select></label><label>Analysis method<select name=backend><option value=baseline>Deterministic evidence baseline</option>");
        if std::env::var_os("ATHERNEX_MODEL_URL").is_some()
            && std::env::var_os("ATHERNEX_MODEL_NAME").is_some()
        {
            html.push_str("<option value=ollama>Configured inference service</option>");
        }
        html.push_str("</select></label><label>Evidence limit<input type=number name=max_events value=16 min=1 max=32 required></label><label>Token budget<input type=number name=token_budget value=4096 min=128 max=16384 required></label><button class=button>Analyze admitted evidence</button></form></section>");
    }
    html.push_str("<section class='panel controls-panel fleet-panel'><h2>Recent analyses</h2>");
    for (id, owner, state) in e
        .investigation_history()
        .map_err(|e| WebError(e.to_string()))?
    {
        write!(
            html,
            "<p><a href='/analysis/{}'>{}</a> · {} · {}</p>",
            escape(&id),
            escape(&id),
            escape(&owner),
            escape(&state)
        )
        .unwrap();
    }
    html.push_str("</section>");
    page(&app, &e, &html)
}
#[derive(Deserialize)]
struct RunForm {
    csrf: String,
    case_id: i64,
    pool: String,
    backend: String,
    max_events: usize,
    token_budget: u64,
}
async fn run_form(
    State(app): State<App>,
    Extension(actor): Extension<Actor>,
    mut headers: HeaderMap,
    Form(form): Form<RunForm>,
) -> Response {
    if !crate::gateway::same_secret(&form.csrf, &app.csrf) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Ok(id) = crate::gateway::secret() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Ok(csrf) = app.csrf.parse() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    headers.insert("x-athernex-csrf", csrf);
    let request = InvestigationRequest {
        id: id.clone(),
        case_id: form.case_id,
        pool: form.pool,
        max_events: form.max_events,
        token_budget: form.token_budget,
        deadline_ms: crate::model::now_ms() + 60000,
    };
    let response = run(
        State(app),
        Extension(actor),
        headers,
        Json(Run {
            request,
            backend: form.backend,
        }),
    )
    .await;
    if response.status().is_success() {
        Redirect::to(&format!("/analysis/{id}")).into_response()
    } else {
        response
    }
}
async fn result_page(
    State(app): State<App>,
    Path(id): Path<String>,
) -> Result<Html<String>, WebError> {
    use crate::render::escape;
    use std::fmt::Write;
    let e = app
        .engine
        .lock()
        .map_err(|_| WebError("Engine unavailable".into()))?;
    let job = e.investigation(&id).map_err(|e| WebError(e.to_string()))?;
    let mut html=format!("<section class=page-heading><div><h1>Investigation result</h1><p>{} · requested by {} · {} reported tokens</p><a class=button href='/case/{}'>Open investigation</a><a class=button href=/analysis>All analyses</a></div></section>",escape(&job.state),escape(&job.owner),job.tokens_used,job.packet.request.case_id);
    if !job.error.is_empty() {
        write!(html,"<section class='panel controls-panel fleet-panel'><h2>Analysis held</h2><p>{}</p></section>",escape(&job.error)).unwrap();
    }
    if let Some(analysis) = job.analysis {
        html.push_str(
            "<section class='panel controls-panel fleet-panel'><h2>Verified observations</h2>",
        );
        for fact in analysis.facts {
            write!(
                html,
                "<p><a href='/event/{}'>Evidence {}</a> · {}: <code>{}</code></p>",
                fact.event_id,
                fact.event_id,
                escape(&fact.field),
                escape(&fact.value.to_string())
            )
            .unwrap();
        }
        html.push_str("</section><section class='panel controls-panel fleet-panel'><h2>Unverified hypotheses</h2>");
        if analysis.hypotheses.is_empty() {
            html.push_str("<p>No hypotheses proposed.</p>");
        }
        for hypothesis in analysis.hypotheses {
            write!(html, "<p>{}</p>", escape(&hypothesis)).unwrap();
        }
        if let Some(reason) = analysis.abstain_reason {
            write!(
                html,
                "<h3>Limits of this analysis</h3><p>{}</p>",
                escape(&reason)
            )
            .unwrap();
        }
        html.push_str("</section>");
    }
    page(&app, &e, &html)
}
fn mutation(app: &App, actor: &Actor, headers: &HeaderMap) -> bool {
    actor.role != Role::Viewer
        && (!crate::fleet_web::bearer(headers).is_empty()
            || headers
                .get("x-athernex-csrf")
                .and_then(|h| h.to_str().ok())
                .is_some_and(|s| crate::gateway::same_secret(s, &app.csrf)))
}
async fn run(
    State(app): State<App>,
    Extension(actor): Extension<Actor>,
    headers: HeaderMap,
    Json(run): Json<Run>,
) -> Response {
    if !mutation(&app, &actor, &headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let provider=match run.backend.as_str() {
        "baseline"=>None,
        "ollama"=>match (std::env::var("ATHERNEX_MODEL_URL"),std::env::var("ATHERNEX_MODEL_NAME")) {
            (Ok(url),Ok(model))=>Some((url,model)),
            _=>return WebError("Configure ATHERNEX_MODEL_URL and ATHERNEX_MODEL_NAME before requesting model analysis".into()).into_response(),
        },
        _=>return WebError("Unknown investigation backend".into()).into_response(),
    };
    let Ok(permit) = WORKERS
        .get_or_init(|| Arc::new(tokio::sync::Semaphore::new(2)))
        .clone()
        .try_acquire_owned()
    else {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    let packet = match app
        .engine
        .lock()
        .map_err(|_| "Engine unavailable".to_string())
        .and_then(|e| {
            e.prepare_investigation(&run.request, &actor.id, crate::model::now_ms())
                .map_err(|e| e.to_string())
        }) {
        Ok(packet) => packet,
        Err(error) => return WebError(error).into_response(),
    };
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let result = match provider {
            Some((url, model)) => crate::investigator::ollama(&packet, &url, &model),
            None => Ok((crate::investigator::baseline(&packet), 0)),
        };
        app.engine
            .lock()
            .map_err(|_| "Engine unavailable".to_string())?
            .finish_investigation(&packet.request.id, result, crate::model::now_ms())
            .map_err(|e| e.to_string())
    })
    .await;
    match result {
        Ok(Ok(job)) => Json(job).into_response(),
        Ok(Err(error)) => WebError(error).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
async fn job(
    State(app): State<App>,
    Path(id): Path<String>,
) -> Result<Json<Investigation>, WebError> {
    let e = app
        .engine
        .lock()
        .map_err(|_| WebError("Engine unavailable".into()))?;
    e.investigation(&id)
        .map(Json)
        .map_err(|e| WebError(e.to_string()))
}
async fn cancel(
    State(app): State<App>,
    Extension(actor): Extension<Actor>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !mutation(&app, &actor, &headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Ok(e) = app.engine.lock() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    match e.cancel_investigation(
        &id,
        &actor.id,
        actor.role == Role::Admin,
        crate::model::now_ms(),
    ) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => WebError(error.to_string()).into_response(),
    }
}
